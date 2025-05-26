import os
import logging
from vt_scanner import VirusTotalScanner
from volatility_wrapper import VolatilityWrapper
from data_processing import filter_netscan_output, filter_user_assist

class MemoryAnalyzer:
    """
    Encapsulates the core workflow of Volatility-based memory analysis, scanning,
    dumping suspicious processes, and checking them with VirusTotal.
    """
    def __init__(self, memory_image, volatility_path, vt_api_keys):
        self.memory_image = memory_image
        self.volatility_path = volatility_path

        # Create output directory for analysis
        self.output_dir = os.path.join(os.getcwd(), "memory_analysis")
        os.makedirs(self.output_dir, exist_ok=True)

        # Initialize wrappers
        self.vol_wrapper = VolatilityWrapper(self.volatility_path, self.memory_image, self.output_dir)
        self.vt_scanner = VirusTotalScanner(vt_api_keys)

    def dump_and_scan_processes(self, pids_to_check, dump_dir):
        """
        Dumps the memory of given PIDs, then scans the dumped files with VirusTotal.
        """
        for pid in pids_to_check:
            pid_path = os.path.join(dump_dir, f"PID_{pid}")
            os.makedirs(pid_path, exist_ok=True)
            dumped_files = self.vol_wrapper.dump_memory(pid, pid_path)
            if not dumped_files:
                logging.warning(f"No dump files found for PID {pid}")
                continue

            for filepath in dumped_files:
                scan_result = self.vt_scanner.scan_file_with_virustotal(filepath)
                while scan_result == {"error": "Rate limit reached"}:
                    logging.warning("Rate limit reached. Waiting for 15 seconds to retry.")
                    import time
                    time.sleep(15)
                    self.vt_scanner.rotate_key_after_request()
                    scan_result = self.vt_scanner.scan_file_with_virustotal(filepath)
                if scan_result:
                    self.vt_scanner.vt_file_results.append(scan_result)
                self.vt_scanner.rotate_key_after_request()

        # Sort results in descending order by detection count
        self.vt_scanner.vt_file_results.sort(key=lambda x: x.get('virustotal_detected', 0), reverse=True)

        # Save file scan results
        results_file = os.path.join(self.output_dir, "virustotal_results.json")
        import json
        with open(results_file, "w") as outfile:
            json.dump(self.vt_scanner.vt_file_results, outfile, indent=4)

    def check_malicious_ips(self, pids_to_check=None):
        """
        Runs Volatility's netscan, reconstructs IP connections, checks the IPs with VirusTotal,
        then dumps and scans processes that connect to malicious IPs.
        """
        if pids_to_check is None:
            pids_to_check = set()

        logging.info("Starting malicious IP detection.")
        netscan_out, _ = self.vol_wrapper.run_volatility_command("netscan")
        if not netscan_out:
            logging.error("Netscan data is missing; cannot proceed with IP detection.")
            return None

        combined_data, foreign_addrs = filter_netscan_output(netscan_out)
        if not combined_data or not foreign_addrs:
            logging.error("Failed to filter netscan output.")
            return None

        filtered_netscan_path = os.path.join(self.output_dir, "filtered_netscan_with_IPcheck.json")

        # Collect newly scanned IPs
        scanned_ips = []
        for ip in foreign_addrs:
            if ip not in self.vt_scanner.vt_ip_results:
                ip_result = self.vt_scanner.scan_ip_with_virustotal(ip)
                while ip_result == {"error": "Rate limit reached"}:
                    logging.warning("Rate limit reached for IP scanning. Waiting for 15 seconds to retry.")
                    import time
                    time.sleep(15)
                    self.vt_scanner.rotate_key_after_request()
                    ip_result = self.vt_scanner.scan_ip_with_virustotal(ip)
                if ip_result:
                    self.vt_scanner.vt_ip_results[ip] = ip_result
                    scanned_ips.append(ip)
                self.vt_scanner.rotate_key_after_request()
            else:
                scanned_ips.append(ip)

        # Mark malicious IPs
        malicious_pids = set()
        for group in combined_data.get("GroupedConnections", []):
            owner = group.get("Owner")
            has_malicious_ip = False
            for connection in group.get("Connections", []):
                f_ip = connection.get("ForeignAddr")
                pid = connection.get("pid")
                if f_ip in self.vt_scanner.vt_ip_results:
                    connection["VT_Results"] = self.vt_scanner.vt_ip_results[f_ip]
                    is_mal = self.vt_scanner.vt_ip_results[f_ip].get("is_malicious", False)
                    if is_mal:
                        has_malicious_ip = True
                        for owner_info in combined_data["UniqueOwners"]:
                            if owner_info["PID"] == pid and owner_info["Owner"] == owner:
                                if f_ip not in owner_info["Malicious_IP"]:
                                    owner_info["Malicious_IP"].append(f_ip)
                        # Record that we should dump & scan this PID
                        if pid and pid not in pids_to_check:
                            malicious_pids.add(pid)
            group["Has_Malicious_IP"] = has_malicious_ip

        # Mark malicious owners
        for owner_info in combined_data["UniqueOwners"]:
            owner_info["Has_Malicious_IP"] = bool(owner_info["Malicious_IP"])

        # Sort them so malicious ones come first
        combined_data["UniqueOwners"].sort(key=lambda x: x.get("Has_Malicious_IP"), reverse=True)
        combined_data["GroupedConnections"].sort(key=lambda x: x.get("Has_Malicious_IP"), reverse=True)

        # Dump memory for malicious processes
        if malicious_pids:
            logging.info(f"Dumping and scanning processes with malicious connections: {malicious_pids}")
            dump_dir = os.path.join(self.output_dir, "dumped_memory_malicious_ips")
            os.makedirs(dump_dir, exist_ok=True)
            self.dump_and_scan_processes(malicious_pids, dump_dir)

        # Sort IP results so malicious IPs show first
        vt_ip_results_list = list(self.vt_scanner.vt_ip_results.values())
        vt_ip_results_list.sort(
            key=lambda x: (x.get('malicious_count', 0), x.get('suspicious_count', 0)),
            reverse=True
        )
        ip_results_output = {
            "foreign_ips_scanned": scanned_ips,
            "ip_analysis_results": vt_ip_results_list
        }

        import json
        with open(filtered_netscan_path, "w") as outfile:
            json.dump(combined_data, outfile, indent=4)

        ip_out_file = os.path.join(self.output_dir, "virustotal_ip_results.json")
        with open(ip_out_file, "w") as outfile:
            json.dump(ip_results_output, outfile, indent=4)

        logging.info("Malicious IP detection completed.")
        return filtered_netscan_path

    def find_malicious_processes(self):
        """
        Runs Volatility's malfind, collects suspicious PIDs, then extends the list
        to include child processes from pslist, then dumps & scans them.
        Finally, checks for malicious IP connections.
        """
        logging.info("Starting malicious process detection.")
        _, malfind_data = self.vol_wrapper.run_volatility_command("malfind")
        _, pslist_data = self.vol_wrapper.run_volatility_command("pslist")

        if not malfind_data or not pslist_data:
            logging.error("No malfind or pslist data; cannot proceed.")
            return

        pids_to_check = set()
        for entry in malfind_data:
            pids_to_check.add(entry.get("PID"))
        for process in pslist_data:
            if process.get("PPID") in pids_to_check:
                pids_to_check.add(process.get("PID"))

        logging.info(f"PIDs to check: {pids_to_check}")

        # Dump suspicious processes
        dump_dir = os.path.join(self.output_dir, "dumped_memory")
        os.makedirs(dump_dir, exist_ok=True)
        self.dump_and_scan_processes(pids_to_check, dump_dir)

        logging.info("Malicious process detection completed.")
        # Next, check for malicious IP connections
        self.check_malicious_ips(pids_to_check)

    def full_automation(self):
        """
        Runs a thorough automation:
        1) find_malicious_processes
        2) run userassist
        3) run wininfo
        4) run cmdline
        """
        logging.info("Starting full automation.")
        self.find_malicious_processes()

        userassist_output, _ = self.vol_wrapper.run_volatility_command("userassist")
        if userassist_output:
            from data_processing import filter_user_assist
            filtered_userassist_path = os.path.join(self.output_dir, "filtered_userassist.json")
            filter_user_assist(userassist_output, filtered_userassist_path)

        self.vol_wrapper.run_volatility_command("wininfo")
        self.vol_wrapper.run_volatility_command("cmdline")
        logging.info("Full automation completed.")
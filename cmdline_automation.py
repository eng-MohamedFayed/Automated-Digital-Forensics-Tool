import json
import os
import subprocess
from time import sleep
import requests
import hashlib
import re
import sys
import ctypes
import logging
from tkinter import Tk, filedialog

class MemoryAnalyzer:
    def __init__(self):
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,  # Set to DEBUG for more detailed output
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='memory_analysis.log',  # Log messages will be written to this file
            filemode='a'  # Append to the log file instead of overwriting
        )

        # Initialize variables
        self.memory_image = None
        self.volatility_path = None
        self.output_dir = os.path.join(os.getcwd(), "memory_analysis")
        os.makedirs(self.output_dir, exist_ok=True)
        self.commands = {}
        self.vt_api_keys = []
        self.vt_key_turn = 0
        self.vt_key_use_counter = 0
        self.vt_file_results = []
        self.vt_ip_results = {}
        self.vt_file_results_ips = []

        # Ask the user how they want to acquire the memory dump
        Tk().withdraw()

        # Load VirusTotal API keys
        try:
            with open("vt_accounts.json", "r") as f:
                vt_accounts = json.load(f)
            for entry in vt_accounts:
                api_key = entry.get("APIKEY")
                if api_key != "":
                    self.vt_api_keys.append(api_key)
            logging.info(f"Loaded {len(self.vt_api_keys)} VirusTotal API keys.")
        except Exception as e:
            logging.error(f"Error loading VirusTotal API keys: {e}")
            sys.exit(1)

        while not self.memory_image or not self.volatility_path:
            choice = input("Memory acquisition:\n1) Live acquisition\n2) Manual selection\n3) Exit\nChoose (1/2/3): ")
            if choice == "1":
                try:
                    is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
                except Exception as e:
                    is_admin = False
                    logging.error(f"Error checking admin privileges: {e}")

                if not is_admin:
                    consent = input("Live acquisition requires admin privileges. Proceed? (y/n): ")
                    if consent.lower() == "y":
                        # Re-run script as admin
                        logging.info("Re-running script as admin for live acquisition.")
                        ctypes.windll.shell32.ShellExecuteW(
                            None, "runas", sys.executable, " ".join(sys.argv), None, 1
                        )
                        sys.exit(0)
                    else:
                        logging.info("Live acquisition canceled by user.")
                        sys.exit(0)

                logging.info("Acquiring live memory image with winpmem...")
                winpmem_path = r"winpmem_mini_x64_rc2.exe"  # Adjust path as needed
                acquired_file = os.path.join(os.getcwd(), "live_memory_dump.mem")
                try:
                    subprocess.run([winpmem_path, acquired_file], check=True)
                    self.memory_image = acquired_file
                    logging.info(f"Live memory acquired and saved to {acquired_file}.")
                except subprocess.CalledProcessError as e:
                    logging.error(f"Failed to acquire live memory: {e}")
                    sys.exit(1)

            elif choice == "2":
                logging.info("User chose manual selection of memory dump file.")
                self.memory_image = filedialog.askopenfilename(
                    title="Select Memory Dump File",
                    filetypes=[("Memory Dump Files", "*.mem *.dmp *.bin"), ("All Files", "*.*")]
                )
                if not self.memory_image:
                    logging.warning("No memory dump file selected. Please try again.")
                    continue
                else:
                    logging.info(f"Memory dump file selected: {self.memory_image}")
            elif choice == "3":
                logging.info("Exiting memory acquisition.")
                sys.exit(0)
            else:
                logging.warning("Invalid choice for memory acquisition.")

            logging.info("Prompting user to select Volatility script path.")
            self.volatility_path = filedialog.askopenfilename(
                title="Select Volatility Script",
                filetypes=[("Python Files", "*.py"), ("All Files", "*.*")]
            )
            if not self.volatility_path:
                logging.warning("No Volatility script selected. Please try again.")
                continue
            else:
                logging.info(f"Volatility script selected: {self.volatility_path}")

        # Initialize commands after memory_image and volatility_path are set
        self.commands = {
            "pslist": ["python", self.volatility_path, "-f", self.memory_image, "windows.pslist.PsList"],
            "netscan": ["python", self.volatility_path, "-f", self.memory_image, "windows.netscan.NetScan"],
            "wininfo": ["python", self.volatility_path, "-f", self.memory_image, "windows.info.Info"],
            "userassist": ["python", self.volatility_path, "-f", self.memory_image, "windows.registry.userassist.UserAssist"],
            "malfind": ["python", self.volatility_path, "-f", self.memory_image, "windows.malfind.Malfind"],
            "cmdline": ["python", self.volatility_path, "-f", self.memory_image, "windows.cmdline.CmdLine"],
            "pstree": ["python", self.volatility_path, "-f", self.memory_image, "windows.pstree.PsTree"],
        }

    def parse_volatility_output(self, output_lines, command_name):
        """
        Parse Volatility3 output and return the data as a list of dictionaries.

        Args:
            output_lines (list): List of lines from the Volatility3 output.
            command_name (str): Name of the command being parsed.

        Returns:
            list: List of dictionaries containing the parsed data.
        """
        headers = output_lines[2].split()
        data = []

        if command_name == "malfind":
            data = []
            current_entry = None

            for line in output_lines[4:]:
                # Parse the metadata line
                if line.split() and line.split()[0].isdigit() and (len(line.split()) == 10 or len(line.split()) == 11):
                    # Start of a new entry
                    if current_entry:  # Save the previous entry
                        data.append(current_entry)
                    fields = line.split()
                    current_entry = {
                        "PID": fields[0],
                        "Process": fields[1],
                        "Start VPN": fields[2],
                        "End VPN": fields[3],
                        "Tag": fields[4],
                        "Protection": fields[5],
                        "CommitCharge": fields[6],
                        "PrivateMemory": fields[7],
                        "File output": fields[8],
                        "Notes": fields[9] + " " + fields[10] if len(fields) > 10 else fields[9],
                        "Hexdump": [],
                        "Disasm": []
                    }
                elif current_entry is not None:
                    # Determine whether it's Hexdump or Disasm
                    if all(c in "0123456789abcdefABCDEF .-" for c in line.split()[0]):
                        # Hexdump section
                        current_entry["Hexdump"].append(line.strip())
                    elif ":" in line and line.split(":")[1].strip():
                        # Disassembly section
                        current_entry["Disasm"].append(line)

            # Add the last entry
            if current_entry:
                data.append(current_entry)

            return data

        elif command_name == "netscan":
            for line in output_lines[4:]:
                values = line.split()
                if values and (values[1] in ["UDPv4", "UDPv6"]):
                    # To insert N/A in the empty field of state
                    values.insert(6, "N/A")
                entry = dict(zip(headers, values))
                if entry:
                    data.append(entry)
            return data
        elif command_name == "pslist":
            # Custom parsing for pslist to handle spaces in ImageFileName
            header_line = output_lines[2]
            headers = ['PID', 'PPID', 'ImageFileName', 'Offset(V)', 'Threads', 'Handles', 'SessionId', 'Wow64', 'CreateTime', 'ExitTime', 'File output']
            data = []

            for line in output_lines[3:]:
                line = line.strip()
                if not line:
                    continue  # Skip empty lines
                tokens = line.split()
                # Read PID and PPID
                pid = tokens[0]
                ppid = tokens[1]
                tokens = tokens[2:]

                # Extract ImageFileName until we reach Offset(V)
                image_file_name_tokens = []
                offset_v = None
                for idx, token in enumerate(tokens):
                    if re.match(r'^0x[0-9a-fA-F]+$', token):
                        offset_v = token
                        remaining_tokens = tokens[idx+1:]
                        break
                    else:
                        image_file_name_tokens.append(token)
                else:
                    # Offset(V) not found, skip this line
                    logging.warning(f"Offset(V) not found in line: {line}")
                    continue

                image_file_name = ' '.join(image_file_name_tokens)

                if len(remaining_tokens) >= 7:
                    threads = remaining_tokens[0]
                    handles = remaining_tokens[1]
                    session_id = remaining_tokens[2]
                    wow64 = remaining_tokens[3]
                    create_time = ' '.join(remaining_tokens[4:7])  # CreateTime may contain spaces
                    exit_time = remaining_tokens[7]
                    file_output = ' '.join(remaining_tokens[8:])
                else:
                    logging.warning(f"Not enough tokens remaining in line after Offset(V): {line}")
                    continue

                entry = {
                    'PID': pid,
                    'PPID': ppid,
                    'ImageFileName': image_file_name,
                    'Offset(V)': offset_v,
                    'Threads': threads,
                    'Handles': handles,
                    'SessionId': session_id,
                    'Wow64': wow64,
                    'CreateTime': create_time,
                    'ExitTime': exit_time,
                    'File output': file_output
                }
                data.append(entry)
            return data

        else:
            for line in output_lines[4:]:
                values = line.split()
                entry = dict(zip(headers, values))
                if entry:
                    data.append(entry)
            return data

    def run_volatility_command(self, command_name, command, output_dir=None):
        """
        Run a Volatility3 command and save its output as JSON.

        Args:
            command_name (str): Name of the command being run.
            command (list): Command to execute.
            output_dir (str): Directory to save the output file. If None, uses self.output_dir.

        Returns:
            tuple: Path to the output JSON file and the parsed data.
        """
        if output_dir is None:
            output_dir = self.output_dir

        output_file = os.path.join(output_dir, f"{command_name}.json")
        try:
            logging.info(f"Running Volatility command: {command_name}")
            result = subprocess.run(command, text=True, capture_output=True, shell=True)
            output_lines = result.stdout.splitlines()

            if len(output_lines) < 3:
                logging.warning(f"No data returned for {command_name}.")
                return None, None

            data = self.parse_volatility_output(output_lines, command_name)

            with open(output_file, "w") as outfile:
                json.dump(data, outfile, indent=4)

            logging.info(f"{command_name} output saved to {output_file}")
            return output_file, data
        except Exception as e:
            logging.error(f"Error running {command_name}: {e}")
            return None, None

    def dump_memory(self, pid, dump_dir):
        """
        Dump memory for a given PID using Volatility.

        Args:
            pid (str): Process ID to dump.
            dump_dir (str): Directory to save dumped memory files.

        Returns:
            list: Paths to the dumped files, or None if dumping fails.
        """
        try:
            logging.info(f"Dumping memory for PID {pid}")
            volatility_command = [
                "python", self.volatility_path,
                "-f", self.memory_image,
                "-o", dump_dir,
                "windows.dumpfiles.DumpFiles",
                "--pid", str(pid)
            ]
            # Run the command
            self.run_volatility_command(f"dumpfiles_{pid}", volatility_command, dump_dir)

            # Find dumped .exe or .dll files in dump_dir
            paths = []
            for file_name in os.listdir(dump_dir):
                if file_name.lower().endswith((".exe", ".dll", ".exe.img", ".dll.img")):
                    paths.append(os.path.join(dump_dir, file_name))
            if paths:
                logging.info(f"Dumped files for PID {pid}: {paths}")
            else:
                logging.warning(f"No dumped executable files found for PID {pid}")
            return paths
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to dump memory for PID {pid}: {e.stderr}")
        except Exception as e:
            logging.error(f"Error dumping memory for PID {pid}: {e}")

        return None

    def scan_file_with_virustotal(self, file_path):
        """
        Upload a file to VirusTotal for scanning and return the result with essential data for investigation.

        Args:
            file_path (str): Path to the file to be uploaded.

        Returns:
            dict: Simplified JSON response from VirusTotal with key investigative details.
        """
        try:
            logging.info(f"Scanning file with VirusTotal: {file_path}")
            with open(file_path, 'rb') as file:
                data = file.read()

            file_data = {
                'filename': os.path.basename(file_path),
                'full_path': file_path,
                'file_size': os.path.getsize(file_path),
                'md5': hashlib.md5(data).hexdigest(),
                'sha256': hashlib.sha256(data).hexdigest(),
            }

            headers = {"x-apikey": self.vt_api_keys[self.vt_key_turn]}
            response = requests.get(
                f"https://www.virustotal.com/api/v3/files/{file_data['sha256']}",
                headers=headers
            )

            if response.status_code == 200:
                result = response.json()
                attributes = result.get('data', {}).get('attributes', {})

                # Malware detection summary
                last_analysis_stats = attributes.get('last_analysis_stats', {})
                file_data['virustotal_detected'] = last_analysis_stats.get('malicious', 0)
                file_data['total_scans'] = sum(last_analysis_stats.values())
                file_data['malware_status'] = 'Malicious' if file_data['virustotal_detected'] > 0 else 'Clean'

                # Detection details
                last_analysis_results = attributes.get('last_analysis_results', {})
                detections = []
                for engine_name, engine_data in last_analysis_results.items():
                    if engine_data.get('category') == 'malicious':
                        detections.append({
                            'engine_name': engine_name,
                            'result': engine_data.get('result')
                        })
                file_data['detections'] = detections

                # Behavioral tags
                file_data['tags'] = attributes.get('tags', [])

                # Reputation score
                file_data['reputation'] = attributes.get('reputation')

                # Sandbox analysis summary (if available)
                sandbox_verdicts = attributes.get('sandbox_verdicts', {})
                sandbox_summaries = []
                for sandbox_name, verdict in sandbox_verdicts.items():
                    sandbox_summaries.append({
                        'sandbox_name': sandbox_name,
                        'category': verdict.get('category'),
                        'malware_classification': verdict.get('malware_classification'),
                    })
                file_data['sandbox_analysis'] = sandbox_summaries

                logging.info(f"VirusTotal scan completed for {file_path}: {file_data['malware_status']}")
                return file_data

            elif response.status_code == 429:
                logging.warning(f"Rate limit reached for current API key while scanning file {file_path}.")
                return {"error": "Rate limit reached"}

            elif response.status_code == 404:
                # File not found in VirusTotal, upload it
                logging.info(f"File {file_path} not found in VirusTotal. Uploading for analysis.")
                with open(file_path, 'rb') as file:
                    response = requests.post(
                        "https://www.virustotal.com/api/v3/files",
                        headers=headers,
                        files={"file": (file_data['filename'], file)}
                    )
                if response.status_code in (200, 201):
                    result = response.json()
                    # Wait for analysis completion
                    analysis_id = result.get('data', {}).get('id')
                    if analysis_id:
                        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                        while True:
                            analysis_response = requests.get(analysis_url, headers=headers)
                            analysis_result = analysis_response.json()
                            status = analysis_result.get('data', {}).get('attributes', {}).get('status')
                            if status == 'completed':
                                attributes = analysis_result.get('data', {}).get('attributes', {})
                                stats = attributes.get('stats', {})
                                file_data['malicious_detections'] = stats.get('malicious', 0)
                                file_data['total_scans'] = sum(stats.values())
                                file_data['malware_status'] = 'Malicious' if file_data['malicious_detections'] > 0 else 'Clean'

                                # Extract detection details
                                results = attributes.get('results', {})
                                detections = []
                                for engine_name, engine_data in results.items():
                                    if engine_data.get('category') == 'malicious':
                                        detections.append({
                                            'engine_name': engine_name,
                                            'result': engine_data.get('result')
                                        })
                                file_data['detections'] = detections

                                # Behavioral tags
                                file_data['tags'] = attributes.get('tags', [])

                                logging.info(f"VirusTotal analysis completed for {file_path}: {file_data['malware_status']}")
                                return file_data
                            else:
                                logging.info("Waiting for VirusTotal analysis to complete...")
                                sleep(15)
                    else:
                        logging.error("No analysis ID returned from VirusTotal.")
                        return None
                else:
                    logging.error(f"Error uploading {file_path} to VirusTotal: {response.status_code} {response.text}")
                    return None

            else:
                logging.error(f"Error scanning {file_path} with VirusTotal: {response.status_code} {response.text}")
                return None

        except Exception as e:
            logging.error(f"Error checking {file_path} in VirusTotal: {e}")
            return None

    def scan_ip_with_virustotal(self, ip):
        """
        Check an IP address against VirusTotal's IP address database and return essential information.

        Args:
            ip (str): IP address to check.

        Returns:
            dict: Simplified JSON response from VirusTotal with key investigative details.
        """
        try:
            logging.info(f"Scanning IP with VirusTotal: {ip}")
            headers = {"x-apikey": self.vt_api_keys[self.vt_key_turn]}
            response = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers=headers
            )
            if response.status_code == 200:
                result = response.json()
                attributes = result.get("data", {}).get("attributes", {})

                # Essential IP information
                data = {
                    "ip_address": ip,
                    "country": attributes.get("country"),
                    "asn": attributes.get("asn"),
                    "as_owner": attributes.get("as_owner"),
                    "reputation": attributes.get("reputation"),
                    "tags": attributes.get("tags", []),
                    "last_modification_date": attributes.get("last_modification_date"),
                }

                # Last analysis stats
                last_analysis_stats = attributes.get("last_analysis_stats", {})
                malicious_count = last_analysis_stats.get("malicious", 0)
                suspicious_count = last_analysis_stats.get("suspicious", 0)
                data['malicious_count'] = malicious_count
                data['suspicious_count'] = suspicious_count
                data['total_scans'] = sum(last_analysis_stats.values())
                data["is_malicious"] = malicious_count > 0 or suspicious_count > 0

                # Detection details
                last_analysis_results = attributes.get('last_analysis_results', {})
                detections = []
                for engine_name, engine_data in last_analysis_results.items():
                    category = engine_data.get('category')
                    if category in ['malicious', 'suspicious']:
                        detections.append({
                            'engine_name': engine_name,
                            'category': category,
                            'result': engine_data.get('result')
                        })
                data['detections'] = detections

                logging.info(f"VirusTotal scan completed for IP {ip}: {'Malicious' if data['is_malicious'] else 'Clean'}")
                return data

            elif response.status_code == 429:
                logging.warning(f"Rate limit reached for current API key while scanning IP {ip}.")
                return {"error": "Rate limit reached"}

            else:
                logging.error(f"Error scanning IP {ip} with VirusTotal: {response.status_code} {response.text}")
                return None

        except Exception as e:
            logging.error(f"Error scanning IP {ip} in VirusTotal: {e}")
            return None

    def filter_netscan_output(self, netscan_json_path):
        """
        Filter the netscan JSON output to include unique owners and group connections under their respective owners.
        Stores both results in a single JSON file.

        Args:
            netscan_json_path (str): Path to the netscan output JSON file.

        Returns:
            tuple: Combined JSON data containing unique owners and grouped connections, and a set of unique ForeignAddr.
        """
        try:
            logging.info(f"Filtering netscan output: {netscan_json_path}")
            with open(netscan_json_path, 'r') as f:
                netscan_data = json.load(f)

            # Step 1: Extract unique owners
            # Collect unique pairs of Owner and PID
            unique_owners = {(entry.get("Owner"), entry.get("PID")) for entry in netscan_data if entry.get("Owner") and entry.get("PID")}
            # Format the unique pairs into the desired JSON structure
            unique_owners_data = [{"Owner": owner, "PID": pid, "Malicious_IP": []} for owner, pid in unique_owners]

            # Step 2: Group connections under their respective owners
            owner_connections = {}
            foreign_addrs = set()  # Collect all unique ForeignAddr for scanning

            for entry in netscan_data:
                owner = entry.get("Owner", "Unknown")
                if owner not in owner_connections:
                    owner_connections[owner] = []
                owner_connections[owner].append({
                    "protocol": entry.get("Proto"),
                    "State": entry.get("State"),
                    "LocalAddr": entry.get("LocalAddr"),
                    "LocalPort": entry.get("LocalPort"),
                    "ForeignAddr": entry.get("ForeignAddr"),
                    "ForeignPort": entry.get("ForeignPort"),
                    "pid": entry.get("PID")
                })
                ip = entry.get("ForeignAddr")
                if ip and ip != "*" and not re.match(
                    r"^(::|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1]))",
                    ip
                ):  # Collect ForeignAddr if present
                    foreign_addrs.add(ip)

            grouped_connections_data = [{"Owner": owner, "Connections": connections}
                                        for owner, connections in owner_connections.items()]

            # Combine the results
            combined_data = {
                "UniqueOwners": unique_owners_data,
                "GroupedConnections": grouped_connections_data
            }

            logging.info("Netscan output filtered successfully.")
            return combined_data, foreign_addrs

        except Exception as e:
            logging.error(f"Error filtering netscan output: {e}")
            return None, None

    def filter_user_assist(self, userassist_json_path, output_path):
        """
        Load and filter valid entries from the userassist JSON output and save to a new file.

        Args:
            userassist_json_path (str): Path to the userassist output JSON file.
            output_path (str): Path to save the filtered JSON file.

        Returns:
            list: Filtered list of valid entries.
        """
        try:
            logging.info(f"Filtering userassist output: {userassist_json_path}")
            with open(userassist_json_path, 'r') as f:
                userassist_data = json.load(f)

            valid_entries = []
            for entry in userassist_data:
                hive = entry.get("Hive")
                offset = entry.get("Offset")

                # Validate entry
                if len(hive) > 2 or len(offset) > 2 or hive.startswith("\\\\") or offset.startswith("\\\\") or offset.startswith("0x"):
                    valid_entries.append(entry)

            # Save filtered entries to a new JSON file
            with open(output_path, 'w') as outfile:
                json.dump(valid_entries, outfile, indent=4)

            logging.info(f"Filtered userassist data saved to {output_path}")
            return valid_entries

        except Exception as e:
            logging.error(f"Error filtering userassist data: {e}")
            return None

    def dump_and_scan_processes(self, pids_to_check, dump_dir):
        """
        Dumps the memory of given processes and scans the dumped files with VirusTotal.

        Args:
            pids_to_check (set): Set of process IDs to dump and scan.
            dump_dir (str): Directory to save dumped memory files.
        """
        for pid in pids_to_check:
            pid_path = os.path.join(dump_dir, f"PID_{pid}")
            os.makedirs(pid_path, exist_ok=True)
            dump_file_paths = self.dump_memory(pid, pid_path)
            if dump_file_paths:
                for path in dump_file_paths:
                    result = self.scan_file_with_virustotal(path)
                    while result == {"error": "Rate limit reached"}:
                        logging.warning("Rate limit reached. Waiting for 15 seconds to retry.")
                        sleep(15)
                        self.vt_key_use_counter += 1
                        if self.vt_key_use_counter % 4 == 0:
                            self.vt_key_turn = (self.vt_key_turn + 1) % len(self.vt_api_keys)
                        result = self.scan_file_with_virustotal(path)
                    if result:
                        self.vt_file_results.append(result)
                    self.vt_key_use_counter += 1
                    if self.vt_key_use_counter % 4 == 0:
                        self.vt_key_turn = (self.vt_key_turn + 1) % len(self.vt_api_keys)
            else:
                logging.warning(f"No dump files found for PID {pid}")
        #to sort the results based on the detections by VT
        self.vt_file_results.sort(key=lambda x: x.get('virustotal_detected', 0), reverse=True)

        # Save the VirusTotal file scan results
        with open(os.path.join(self.output_dir, "virustotal_results.json"), "w") as outfile:
            json.dump(self.vt_file_results, outfile, indent=4)

    def check_malicious_ips(self, pids_to_check=None):
        """
        Run netscan, filter its output to check for malicious IPs, and display their processes.
        Also dump and scan processes that are connected to malicious IPs.

        Args:
            pids_to_check (set): Set of PIDs already checked (to avoid duplication)
        """
        if pids_to_check is None:
            pids_to_check = set()

        logging.info("Starting malicious IP detection.")
        netscan_path, _ = self.run_volatility_command("netscan", self.commands["netscan"])
        if not netscan_path:
            logging.error("Netscan data is missing. Cannot proceed with IP detection.")
            return None

        combined_data, foreign_addrs = self.filter_netscan_output(netscan_path)
        if not combined_data or not foreign_addrs:
            logging.error("Failed to filter netscan output.")
            return None

        filtered_netscan_path = os.path.join(self.output_dir, "filtered_netscan_with_IPcheck.json")

        # List to keep track of all scanned foreign IPs
        scanned_ips = []

        for ip in foreign_addrs:
            if ip not in self.vt_ip_results:
                ip_result = self.scan_ip_with_virustotal(ip)
                while ip_result == {"error": "Rate limit reached"}:
                    logging.warning("Rate limit reached for IP scanning. Waiting for 15 seconds to retry.")
                    sleep(15)
                    self.vt_key_use_counter += 1
                    if self.vt_key_use_counter % 4 == 0:
                        self.vt_key_turn = (self.vt_key_turn + 1) % len(self.vt_api_keys)
                    ip_result = self.scan_ip_with_virustotal(ip)
                if ip_result:
                    self.vt_ip_results[ip] = ip_result
                    scanned_ips.append(ip)
                self.vt_key_use_counter += 1
                if self.vt_key_use_counter % 4 == 0:
                    self.vt_key_turn = (self.vt_key_turn + 1) % len(self.vt_api_keys)
            else:
                scanned_ips.append(ip)

        # Update combined_data with VirusTotal results
        malicious_pids = set()
        for group in combined_data.get("GroupedConnections", []):
            owner = group.get("Owner")
            has_malicious_ip = False
            for connection in group.get("Connections", []):
                foreign_addr = connection.get("ForeignAddr")
                pid = connection.get("pid")
                if self.vt_ip_results.get(foreign_addr):
                    connection["VT_Results"] = self.vt_ip_results[foreign_addr]
                    if self.vt_ip_results[foreign_addr]["is_malicious"]:
                        has_malicious_ip = True
                        # Update the corresponding owner in UniqueOwners
                        for owner_info in combined_data["UniqueOwners"]:
                            if owner_info.get("PID") == pid and owner_info.get("Owner") == owner:
                                if foreign_addr not in owner_info["Malicious_IP"]:
                                    owner_info["Malicious_IP"].append(foreign_addr)
                        # Collect PIDs with malicious connections
                        if pid not in pids_to_check:
                            malicious_pids.add(pid)
            # Mark the group if it has malicious IP connections
            group["Has_Malicious_IP"] = has_malicious_ip

        # Update UniqueOwners to mark owners with malicious IP connections
        for owner_info in combined_data["UniqueOwners"]:
            # Check if the owner has any malicious IP connections
            owner_info["Has_Malicious_IP"] = bool(owner_info.get("Malicious_IP"))

        # Sort UniqueOwners and GroupedConnections based on Has_Malicious_IP flag
        combined_data["UniqueOwners"].sort(key=lambda x: x.get("Has_Malicious_IP"), reverse=True)
        combined_data["GroupedConnections"].sort(key=lambda x: x.get("Has_Malicious_IP"), reverse=True)

        # Dump and scan processes with malicious connections
        if malicious_pids:
            logging.info(f"Dumping and scanning processes with malicious connections: {malicious_pids}")
            dump_dir = os.path.join(self.output_dir, "dumped_memory_malicious_ips")
            os.makedirs(dump_dir, exist_ok=True)
            self.dump_and_scan_processes(malicious_pids, dump_dir)

        # Rearrange the vt_ip_results to display malicious IPs first based on their detections
        # Convert vt_ip_results to a list for sorting
        vt_ip_results_list = list(self.vt_ip_results.values())
        vt_ip_results_list.sort(
            key=lambda x: (x.get('malicious_count', 0), x.get('suspicious_count', 0)), reverse=True
        )

        # Prepare the final IP results output with the list of scanned IPs
        ip_results_output = {
            "foreign_ips_scanned": scanned_ips,
            "ip_analysis_results": vt_ip_results_list
        }

        # Save the updated netscan data
        with open(filtered_netscan_path, "w") as outfile:
            json.dump(combined_data, outfile, indent=4)

        # Save the VirusTotal IP scan results
        with open(os.path.join(self.output_dir, "virustotal_ip_results.json"), "w") as outfile:
            json.dump(ip_results_output, outfile, indent=4)

        logging.info("Malicious IP detection completed.")
        return filtered_netscan_path
    
    def find_malicious_processes(self):
        logging.info("Starting malicious process detection.")
        _, malfind_data = self.run_volatility_command("malfind", self.commands["malfind"])
        _, pslist_data = self.run_volatility_command("pslist", self.commands["pslist"])

        if not malfind_data or not pslist_data:
            logging.error("Malfind or PsList data is missing. Cannot proceed with malicious process detection.")
            return

        # Dump memory for malicious processes
        dump_dir = os.path.join(self.output_dir, "dumped_memory")
        os.makedirs(dump_dir, exist_ok=True)

        pids_to_check = set()
        for entry in malfind_data:
            pids_to_check.add(entry.get("PID"))
        for process in pslist_data:
            if process.get("PPID") in pids_to_check and process.get("PID") not in pids_to_check:
                pids_to_check.add(process.get("PID"))

        logging.info(f"PIDs to check: {pids_to_check}")

        self.dump_and_scan_processes(pids_to_check, dump_dir)

        logging.info("Malicious process detection completed.")
        self.check_malicious_ips(pids_to_check)

    def full_automation(self):
        logging.info("Starting full automation.")
        self.find_malicious_processes()
        userassist_path, _ = self.run_volatility_command("userassist", self.commands["userassist"])
        if userassist_path:
            filtered_userassist_path = os.path.join(self.output_dir, "filtered_userassist.json")
            self.filter_user_assist(userassist_path, filtered_userassist_path)
        self.run_volatility_command("wininfo", self.commands["wininfo"])
        self.run_volatility_command("cmdline", self.commands["cmdline"])
        logging.info("Full automation completed.")

def main():
    analyzer = MemoryAnalyzer()
    # Create output directory if it doesn't exist
    os.makedirs(analyzer.output_dir, exist_ok=True)

    logging.info("Starting Volatility 3 Automation.")
    while True:
        print("\nChoose the command you want to run:")
        print("1 - Find malicious processes")
        print("2 - Network scan")
        print("3 - UserAssist")
        print("4 - Full automation")
        print("5 - Pick a specific command")
        print("6 - Exit")
        choice = input("Enter your choice: ")
        if choice == "1":
            analyzer.find_malicious_processes()
        elif choice == "2":
            analyzer.check_malicious_ips()
        elif choice == "3":
            userassist_path, _ = analyzer.run_volatility_command("userassist", analyzer.commands["userassist"])
            if userassist_path:
                filtered_userassist_path = os.path.join(analyzer.output_dir, "filtered_userassist.json")
                analyzer.filter_user_assist(userassist_path, filtered_userassist_path)
        elif choice == "4":
            analyzer.full_automation()
        elif choice == "5":
            while True:
                print("\nChoose the command you want to run:")
                print("1 - pslist")
                print("2 - netscan")
                print("3 - wininfo")
                print("4 - userassist")
                print("5 - malfind")
                print("6 - cmdline")
                print("7 - pstree")
                print("8 - Enter command manually")
                print("9 - Back to main menu")
                command_choice = input("Enter your choice: ")
                if command_choice == "1":
                    analyzer.run_volatility_command("pslist", analyzer.commands["pslist"])
                elif command_choice == "2":
                    analyzer.check_malicious_ips()
                elif command_choice == "3":
                    analyzer.run_volatility_command("wininfo", analyzer.commands["wininfo"])
                elif command_choice == "4":
                    userassist_path, _ = analyzer.run_volatility_command("userassist", analyzer.commands["userassist"])
                    if userassist_path:
                        filtered_userassist_path = os.path.join(analyzer.output_dir, "filtered_userassist.json")
                        analyzer.filter_user_assist(userassist_path, filtered_userassist_path)
                elif command_choice == "5":
                    analyzer.run_volatility_command("malfind", analyzer.commands["malfind"])
                elif command_choice == "6":
                    analyzer.run_volatility_command("cmdline", analyzer.commands["cmdline"])
                elif command_choice == "7":
                    analyzer.run_volatility_command("pstree", analyzer.commands["pstree"])
                elif command_choice == "8":
                    command_name = input("Enter the command name (e.g., custom_command): ")
                    custom_command = input("Enter the command (e.g., windows.pslist.PsList): ")
                    analyzer.run_volatility_command(command_name, ["python", analyzer.volatility_path, "-f", analyzer.memory_image, custom_command])
                elif command_choice == "9":
                    break
                else:
                    logging.warning("Invalid command choice. Please choose a valid option.")
                    continue
        elif choice == "6":
            logging.info("Exiting Volatility 3 Automation.")
            break
        else:
            logging.warning("Invalid choice. Please enter a number between 1 and 6.")

    print("Automation complete. Results are saved in the memory_analysis directory.")

if __name__ == "__main__":
    main()
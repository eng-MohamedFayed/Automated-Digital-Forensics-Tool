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

# Configure logging
logging.basicConfig(
    level=logging.INFO,  # Set to DEBUG for more detailed output
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='memory_analysis.log',  # Log messages will be written to this file
    filemode='a'  # Append to the log file instead of overwriting
)

# Ask the user how they want to acquire the memory dump
Tk().withdraw()
choice = input("Memory acquisition:\n1) Live acquisition\n2) Manual selection\nChoose (1/2): ")
memory_image = None
volatility_path = None

while not memory_image:
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
            memory_image = acquired_file
            logging.info(f"Live memory acquired and saved to {acquired_file}.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to acquire live memory: {e}")
            sys.exit(1)

    elif choice == "2":
        logging.info("User chose manual selection of memory dump file.")
        memory_image = filedialog.askopenfilename(
            title="Select Memory Dump File",
            filetypes=[("Memory Dump Files", "*.mem *.dmp *.bin"), ("All Files", "*.*")]
        )
        if not memory_image:
            logging.warning("No memory dump file selected. Please try again.")
            continue
        else:
            logging.info(f"Memory dump file selected: {memory_image}")

    else:
        logging.warning("Invalid choice for memory acquisition.")
        choice = input("Choose (1/2): ")

while not volatility_path:
    logging.info("Prompting user to select Volatility script path.")
    volatility_path = filedialog.askopenfilename(
        title="Select Volatility Script",
        filetypes=[("Python Files", "*.py"), ("All Files", "*.*")]
    )
    if not volatility_path:
        logging.warning("No Volatility script selected. Please try again.")
        continue
    else:
        logging.info(f"Volatility script selected: {volatility_path}")

output_dir = os.path.join(os.getcwd(), "memory_analysis")
commands = {
    "pslist": ["python", volatility_path, "-f", memory_image, "windows.pslist.PsList"],
    "netscan": ["python", volatility_path, "-f", memory_image, "windows.netscan.NetScan"],
    "wininfo": ["python", volatility_path, "-f", memory_image, "windows.info.Info"],
    "userassist": ["python", volatility_path, "-f", memory_image, "windows.registry.userassist.UserAssist"],
    "malfind": ["python", volatility_path, "-f", memory_image, "windows.malfind.Malfind"],
    "cmdline": ["python", volatility_path, "-f", memory_image, "windows.cmdline.CmdLine"],
    "pstree": ["python", volatility_path, "-f", memory_image, "windows.pstree.PsTree"],
}

# Load VirusTotal API keys
vt_api_keys = []
try:
    with open("vt_accounts.json", "r") as f:
        vt_accounts = json.load(f)
    for entry in vt_accounts:
        api_key = entry.get("APIKEY")
        if api_key != "":
            vt_api_keys.append(api_key)
    logging.info(f"Loaded {len(vt_api_keys)} VirusTotal API keys.")
except Exception as e:
    logging.error(f"Error loading VirusTotal API keys: {e}")
    sys.exit(1)

vt_key_turn = 0
vt_key_use_counter = 0
vt_file_results = []
vt_ip_results = {}
vt_file_results_ips = []

def parse_volatility_output(output_lines, command_name):
    """
    Parse Volatility3 output and return the data as a list of dictionaries.

    Args:
        output_lines (list): List of lines from the Volatility3 output.

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
            if line.split()[0].isdigit() and (len(line.split())==10 or len(line.split())==11) :  # Start of a new entry
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
    
    elif command_name=="netscan":
        for line in output_lines[4:]:
            values = line.split()
            if (values[1] in ["UDPv4","UDPv6"]) and values!=[]:
                #to insert N/A in the empty field of state
                values.insert(6, "N/A")
            entry = dict(zip(headers, values))
            if entry != {}:
                data.append(entry)
        return data
    else:
        for line in output_lines[4:]:
            values = line.split()
            entry = dict(zip(headers, values))
            if entry != {}:
                data.append(entry)
        return data


def run_volatility_command(command_name, command, output_dir=output_dir):
    """
    Run a Volatility3 command and save its output as JSON.

    Args:
        command_name (str): Name of the command being run.
        command (list): Command to execute.
        output_dir (str): Directory to save the output file.

    Returns:
        tuple: Path to the output JSON file and the parsed data.
    """
    output_file = os.path.join(output_dir, f"{command_name}.json")
    try:
        logging.info(f"Running Volatility command: {command_name}")
        result = subprocess.run(command, text=True, capture_output=True, shell=True)
        output_lines = result.stdout.splitlines()

        if len(output_lines) < 3:
            logging.warning(f"No data returned for {command_name}.")
            return None, None

        data = parse_volatility_output(output_lines, command_name)

        with open(output_file, "w") as outfile:
            json.dump(data, outfile, indent=4)

        logging.info(f"{command_name} output saved to {output_file}")
        return output_file, data
    except Exception as e:
        logging.error(f"Error running {command_name}: {e}")
        return None, None

def dump_memory(pid, dump_dir):
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
            "python", volatility_path,
            "-f", memory_image,
            "-o", dump_dir,
            "windows.dumpfiles.DumpFiles",
            "--pid", str(pid)
        ]
        # Run the command
        run_volatility_command(f"dumpfiles_{pid}", volatility_command, dump_dir)

        # Find dumped .exe or .dll files in dump_dir
        paths = []
        for file_name in os.listdir(dump_dir):
            if file_name.lower().endswith(".exe") or file_name.lower().endswith(".dll") or \
               file_name.lower().endswith(".exe.img") or file_name.lower().endswith(".dll.img"):
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

def scan_file_with_virustotal(file_path, api_key):
    """
    Upload a file to VirusTotal for scanning and return the result as JSON.

    Args:
        file_path (str): Path to the file to be uploaded.
        api_key (str): VirusTotal API key.

    Returns:
        dict: JSON response from VirusTotal.
    """
    try:
        logging.info(f"Scanning file with VirusTotal: {file_path}")
        with open(file_path, 'rb') as file:
            data = file.read()

        file_data = {
            'filename': os.path.basename(file_path),
            'full_path': file_path,
            'md5': hashlib.md5(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest(),
            'file_size': os.path.getsize(file_path)
        }

        headers = {"x-apikey": api_key}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_data['sha256']}",
            headers=headers
        )
        if response.status_code == 200:
            result = response.json()
            attributes = result.get('data', {}).get('attributes', {})
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            file_data['virustotal_detected'] = last_analysis_stats.get('malicious', 0)
            file_data['virustotal_total'] = sum(last_analysis_stats.values())
            file_data['virustotal_scan_date'] = attributes.get('last_analysis_date', 'N/A')
            file_data['malware_status'] = 'Malicious' if file_data['virustotal_detected'] > 0 else 'Clean'

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
            if response.status_code == 200 or response.status_code == 201:
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
                            last_analysis_stats = attributes.get('stats', {})
                            file_data['virustotal_detected'] = last_analysis_stats.get('malicious', 0)
                            file_data['virustotal_total'] = sum(last_analysis_stats.values())
                            file_data['virustotal_scan_date'] = attributes.get('date', 'N/A')
                            file_data['malware_status'] = 'Malicious' if file_data['virustotal_detected'] > 0 else 'Clean'
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

def scan_ip_with_virustotal(ip, api_key):
    """
    Check an IP address against VirusTotal's IP address database.

    Args:
        ip (str): IP address to check.
        api_key (str): VirusTotal API key.

    Returns:
        dict: JSON response from VirusTotal.
    """
    try:
        logging.info(f"Scanning IP with VirusTotal: {ip}")
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key}
        )
        if response.status_code == 200:
            result = response.json()
            attributes = result.get("data", {}).get("attributes", {})
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            data = {
                "country": attributes.get("country"),
                "asn": attributes.get("asn"),
                "reputation": attributes.get("reputation"),
                "tags": attributes.get("tags"),
                "whois": attributes.get("whois"),
                "last_analysis_results": {},
                "malicious": last_analysis_stats.get("malicious", 0),
                "suspicious": last_analysis_stats.get("suspicious", 0),
                "undetected": last_analysis_stats.get("undetected", 0),
                "harmless": last_analysis_stats.get("harmless", 0),
                "timeout": last_analysis_stats.get("timeout", 0),
                "ISmalicious": False
            }
            # Check if IP is malicious
            if data["malicious"] > 0 or data["suspicious"] > 0:
                data["ISmalicious"] = True

            logging.info(f"VirusTotal scan completed for IP {ip}: {'Malicious' if data['ISmalicious'] else 'Clean'}")
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

def filter_netscan_output(netscan_json_path):
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
        unique_owners_data = [{"Owner": owner, "PID": pid, "Malicious_IP":[]} for owner, pid in unique_owners]

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

def filter_user_assist(userassist_json_path, output_path):
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

def dump_and_scan_processes(pids_to_check, dump_dir):
    """
    Dumps the memory of given processes and scans the dumped files with VirusTotal.

    Args:
        pids_to_check (set): Set of process IDs to dump and scan.
        dump_dir (str): Directory to save dumped memory files.
    """
    global vt_api_keys, vt_file_results, vt_key_use_counter, vt_key_turn

    for pid in pids_to_check:
        pid_path = os.path.join(dump_dir, f"PID_{pid}")
        os.makedirs(pid_path, exist_ok=True)
        dump_file_paths = dump_memory(pid, pid_path)
        if dump_file_paths:
            for path in dump_file_paths:
                result = scan_file_with_virustotal(path, vt_api_keys[vt_key_turn])
                while result == {"error": "Rate limit reached"}:
                    logging.warning("Rate limit reached. Waiting for 15 seconds to retry.")
                    sleep(15)
                    result = scan_file_with_virustotal(path, vt_api_keys[vt_key_turn])
                if result:
                    vt_file_results.append(result)
                vt_key_use_counter += 1
                if vt_key_use_counter % 4 == 0:
                    vt_key_turn = (vt_key_turn + 1) % len(vt_api_keys)
        else:
            logging.warning(f"No dump files found for PID {pid}")
    # Save the VirusTotal file scan results
    with open(os.path.join(output_dir, "virustotal_results.json"), "w") as outfile:
        json.dump(vt_file_results, outfile, indent=4)

def find_malicious_processes():
    global vt_api_keys, vt_file_results, vt_ip_results, vt_key_use_counter, vt_key_turn, output_dir, commands

    logging.info("Starting malicious process detection.")
    _, malfind_data = run_volatility_command("malfind", commands["malfind"])
    _, pslist_data = run_volatility_command("pslist", commands["pslist"])

    if not malfind_data or not pslist_data:
        logging.error("Malfind or PsList data is missing. Cannot proceed with malicious process detection.")
        return

    # Dump memory for malicious processes
    dump_dir = os.path.join(output_dir, "dumped_memory")
    os.makedirs(dump_dir, exist_ok=True)

    pids_to_check = set()
    for entry in malfind_data:
        pids_to_check.add(entry.get("PID"))
        for process in pslist_data:
            if process.get("PPID") in pids_to_check and process.get("PID") not in pids_to_check:
                pids_to_check.add(process.get("PID"))

    logging.debug(f"PIDs to check: {pids_to_check}")

    dump_and_scan_processes(pids_to_check, dump_dir)

    logging.info("Malicious process detection completed.")
    check_malicious_ips(output_dir, commands, vt_api_keys, vt_key_turn, vt_key_use_counter, vt_ip_results,pids_to_check)

def check_malicious_ips(output_dir, commands, vt_api_keys, vt_key_turn, vt_key_use_counter,vt_ip_results, pids_to_check):
    """
    Run netscan, filter its output to check for malicious IPs, and display their processes.
    Also dump and scan processes that are connected to malicious IPs.

    Args:
        output_dir (str): Directory to save the output file.
        commands (dict): Dictionary of Volatility commands.
        vt_api_keys (list): List of VirusTotal API keys.
        vt_key_turn (int): Index of the current VirusTotal API key.
        vt_key_use_counter (int): Counter for the number of API key uses.
        vt_ip_results (dict): Dictionary to store VirusTotal results for IPs.

    Returns:
        str: Path to the filtered netscan JSON file.
    """
    logging.info("Starting malicious IP detection.")
    netscan_path, _ = run_volatility_command("netscan", commands["netscan"])
    if not netscan_path:
        logging.error("Netscan data is missing. Cannot proceed with IP detection.")
        return None

    combined_data, foreign_addrs = filter_netscan_output(netscan_path)
    if not combined_data or not foreign_addrs:
        logging.error("Failed to filter netscan output.")
        return None

    filtered_netscan_path = os.path.join(output_dir, "filtered_netscan_with_IPcheck.json")

    for ip in foreign_addrs:
        if ip not in vt_ip_results:
            ip_result = scan_ip_with_virustotal(ip, vt_api_keys[vt_key_turn])
            while ip_result == {"error": "Rate limit reached"}:
                logging.warning("Rate limit reached for IP scanning. Waiting for 15 seconds to retry.")
                sleep(15)
                ip_result = scan_ip_with_virustotal(ip, vt_api_keys[vt_key_turn])
            if ip_result:
                vt_ip_results[ip] = ip_result
            vt_key_use_counter += 1
            if vt_key_use_counter % 4 == 0:
                vt_key_turn = (vt_key_turn + 1) % len(vt_api_keys)

    # Update combined_data with VirusTotal results
    malicious_pids = set()
    for group in combined_data.get("GroupedConnections", []):
        for connection in group.get("Connections", []):
            foreign_addr = connection.get("ForeignAddr")
            pid = connection.get("pid")
            if vt_ip_results.get(foreign_addr):
                connection["VT_Results"] = vt_ip_results[foreign_addr]
                if vt_ip_results[foreign_addr]["ISmalicious"]:
                    for owner in combined_data.get("UniqueOwners", []):
                        if owner.get("PID") == pid:
                            owner["Malicious_IP"].append(foreign_addr)
                    # Collect PIDs with malicious connections
                    if pid not in pids_to_check:
                        malicious_pids.add(pid)

    # Dump and scan processes with malicious connections
    if malicious_pids:
        logging.info(f"Dumping and scanning processes with malicious connections: {malicious_pids}")
        dump_dir = os.path.join(output_dir, "dumped_memory_malicious_ips")
        os.makedirs(dump_dir, exist_ok=True)
        dump_and_scan_processes(malicious_pids, dump_dir)

    # Save the updated netscan data
    with open(filtered_netscan_path, "w") as outfile:
        json.dump(combined_data, outfile, indent=4)

    # Save the VirusTotal IP scan results
    with open(os.path.join(output_dir, "virustotal_ip_results.json"), "w") as outfile:
        json.dump(vt_ip_results, outfile, indent=4)

    logging.info("Malicious IP detection completed.")
    return filtered_netscan_path

def full_automation(output_dir):
    logging.info("Starting full automation.")
    find_malicious_processes()
    userassist_path, _ = run_volatility_command("userassist", commands["userassist"])
    if userassist_path:
        filtered_userassist_path = os.path.join(output_dir, "filtered_userassist.json")
        filter_user_assist(userassist_path, filtered_userassist_path)
    run_volatility_command("wininfo", commands["wininfo"])
    run_volatility_command("cmdline", commands["cmdline"])
    logging.info("Full automation completed.")

def main():
    # make variables global
    global vt_api_keys, vt_file_results, vt_ip_results, output_dir, volatility_path, memory_image, commands, vt_key_turn, vt_key_use_counter

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

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
            find_malicious_processes()
        elif choice == "2":
            check_malicious_ips(output_dir, commands, vt_api_keys, vt_key_turn, vt_key_use_counter, vt_ip_results)
        elif choice == "3":
            userassist_path, _ = run_volatility_command("userassist", commands["userassist"])
            if userassist_path:
                filtered_userassist_path = os.path.join(output_dir, "filtered_userassist.json")
                filter_user_assist(userassist_path, filtered_userassist_path)
        elif choice == "4":
            full_automation(output_dir)
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
                    run_volatility_command("pslist", commands["pslist"])
                elif command_choice == "2":
                    check_malicious_ips(output_dir, commands, vt_api_keys, vt_key_turn, vt_key_use_counter, vt_ip_results)
                elif command_choice == "3":
                    run_volatility_command("wininfo", commands["wininfo"])
                elif command_choice == "4":
                    userassist_path, _ = run_volatility_command("userassist", commands["userassist"])
                    if userassist_path:
                        filtered_userassist_path = os.path.join(output_dir, "filtered_userassist.json")
                        filter_user_assist(userassist_path, filtered_userassist_path)
                elif command_choice == "5":
                    run_volatility_command("malfind", commands["malfind"])
                elif command_choice == "6":
                    run_volatility_command("cmdline", commands["cmdline"])
                elif command_choice == "7":
                    run_volatility_command("pstree", commands["pstree"])
                elif command_choice == "8":
                    command_name = input("Enter the command name (e.g., custom_command): ")
                    custom_command = input("Enter the command (e.g., windows.pslist.PsList): ")
                    run_volatility_command(command_name, ["python", volatility_path, "-f", memory_image, custom_command])
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
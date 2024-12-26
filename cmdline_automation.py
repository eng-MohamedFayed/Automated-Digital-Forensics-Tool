import json
import os
import subprocess
from time import sleep
import requests
import hashlib
import re
import sys
import ctypes
from tkinter import Tk, filedialog

# Ask the user how they want to acquire the memory dump
Tk().withdraw()
choice = input("Memory acquisition:\n1) Live acquisition\n2) Manual selection\nChoose (1/2): ")
memory_image = None
volatility_path = None
while not memory_image:
    if choice == "1":
        try:
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except:
            is_admin = False

        if not is_admin:
            consent = input("Live acquisition requires admin privileges. Proceed? (y/n): ")
            if consent.lower() == "y":
                # Re-run script as admin
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                sys.exit(0)
            else:
                print("Live acquisition canceled.")
                sys.exit(0)

        print("Acquiring live memory image with winpmem...")
        winpmem_path = r"winpmem_mini_x64_rc2.exe"  # Adjust path as needed
        acquired_file = os.path.join(os.getcwd(), "live_memory_dump.mem")
        subprocess.run([winpmem_path, acquired_file])
        memory_image = acquired_file
        print("Live memory acquired. Proceeding with the script...")
        
    else:
        print("Select your memory dump file.")
        memory_image = filedialog.askopenfilename(
            title="Select Memory Dump File",
            filetypes=[("Memory Dump Files","*.mem *.dmp *.bin"), ("All Files","*.*")]
        )
        if not memory_image:
            print("No file selected. Please try again.")
            continue
        
            
while not volatility_path:
    print("Select your Volatility path.")
    volatility_path = filedialog.askopenfilename(
        title="Select Volatility Script",
        filetypes=[("Python Files","*.py"), ("All Files","*.*")]
    )
    if not volatility_path:
        print("No file selected. Please try again.")
        continue

output_dir = os.path.join(os.getcwd(), "memory_analysis")
commands = {
    "pslist": ["python", volatility_path, "-f", memory_image, "windows.pslist.PsList"],
    "netscan": ["python", volatility_path, "-f", memory_image, "windows.netscan.NetScan"],
    "wininfo": ["python", volatility_path, "-f", memory_image, "windows.info.Info"],
    "userassist": ["python", volatility_path, "-f", memory_image, "windows.registry.userassist.UserAssist"],
    "malfind": ["python", volatility_path, "-f", memory_image, "windows.malfind.Malfind"],
    "cmdline": ["python", volatility_path, "-f", memory_image, "windows.cmdline.CmdLine"],
    "pastree": ["python", volatility_path, "-f", memory_image, "windows.pstree.PsTree"],
}
# Load VirusTotal API keys
vt_api_keys = []
with open("vt_acconts.json", "r") as f:
    vt_accounts = json.load(f)
for entry in vt_accounts:
    api_key = entry.get("APIKEY")
    if api_key != "":
        vt_api_keys.append(api_key)
vt_key_turn=0
vt_key_use_counter=0
vt_file_results = []
vt_ip_results = {}


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
    
    # elif command_name=="pstree":
    #     for line in output_lines[4:]:
    #         values = re.split(r'\s+', line.split(" "))
    #         entry = dict(zip(headers, values))
    #         if entry != {}:
    #             data.append(entry)
    #     return data
    
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
        str: Path to the output JSON file.
    """
    output_file = os.path.join(output_dir, f"{command_name}.json")
    try:
        print(f"Running: {command_name}")
        result = subprocess.run(command, text=True, capture_output=True,shell=True)
        output_lines = result.stdout.splitlines()

        if len(output_lines) < 3:
            print(f"No data returned for {command_name}.")
            return None

        data = parse_volatility_output(output_lines, command_name)

        with open(output_file, "w") as outfile:
            json.dump(data, outfile, indent=4)

        print(f"Output saved to {output_file}")
        return output_file, data
    except Exception as e:
        print(f"Error running {command_name}: {e}")
        return None

def dump_memory(pid, dump_dir):
    """
    Dump memory for a given entry using Volatility.

    Args:
        entry (dict): A valid malfind entry.
        dump_dir (str): Directory to save dumped memory files.
        volatility_path (str): Path to the Volatility3 script.
        memory_image (str): Path to the memory image.

    Returns:
        str: Paths to the dumped .exe file, or None if dumping fails.
    """

    try:
        volatility_command = [
            "python", volatility_path,
            "-f", memory_image,
            "-o", dump_dir,
            "windows.dumpfiles.DumpFiles",
            "--pid", str(pid)
        ]
        #the check=True argument will raise an exception if the command fails
        #shell=True is used to run the command in a new shell
        run_volatility_command("dumpfiles", volatility_command, dump_dir)
        # Find dumped .exe file in dump_dir
        paths=[]
        for file_name in os.listdir(dump_dir):
            # print("file_name: ", file_name)
            if file_name.lower().endswith(".exe.img") or file_name.lower().endswith(".dll.img"):
                # print(os.path.join(dump_dir, file_name))
                paths.append(os.path.join(dump_dir, file_name))
                # print("paths: ", paths)
        return paths
    except subprocess.CalledProcessError as e:
        print(f"Failed to dump memory for PID {pid}: {e.stderr}")

    return None

def scan_file_with_virustotal(file_path, api_key):
    """
    Upload a file to VirusTotal for scanning and return the result as JSON.

    Args:
        file_path (str): Path to the file to be uploaded.
        api_keys (list): List of VirusTotal API keys.

    Returns:
        dict: JSON response from VirusTotal.
    """
    with open(file_path, 'rb') as file:
        try:
            data=file.read()
            file_data = {
                        'filename': os.path.basename(file_path),
                        'full_path': file_path,
                        'md5': hashlib.md5(data).hexdigest(),
                        'sha256': hashlib.sha256(data).hexdigest(),
                        'file_size': os.path.getsize(file_path)
                    }
            response = requests.get(
                f"https://www.virustotal.com/api/v3/files/{file_data['md5']}",
                headers={"x-apikey": api_key} 
            )
            if response.status_code == 200:
                result = response.json()
                file_data['virustotal_detected'] = result.get('positives', 0)
                file_data['virustotal_total'] = result.get('total', 0)
                file_data['virustotal_scan_date'] = result.get('scan_date', 'N/A')
                file_data['malware_status'] = (
                    'Malicious' if result.get('positives', 0) > 0 
                    else 'Clean'
                )
                return file_data
            elif response.status_code == 429:
                # print("Rate limit reached for current API key. Switching to the next key.")
                return {"error": "Rate limit reached"}
            elif response.status_code == 404:
                # File not found in VirusTotal, upload it
                response = requests.post(
                    "https://www.virustotal.com/api/v3/files",
                    headers={"x-apikey": api_key},
                    files={"file": (file_data['filename'], file)}
                )
                if response.status_code == 200:
                    result = response.json()
                    file_data['virustotal_detected'] = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                    file_data['virustotal_total'] = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('harmless', 0)
                    file_data['virustotal_scan_date'] = result.get('data', {}).get('attributes', {}).get('last_analysis_date', 'N/A')
                    file_data['malware_status'] = (
                        'Malicious' if result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0 
                        else 'Clean'
                    )
                    return file_data
            else:
                print(f"Error uploading {file_path}. Status code: {response.status_code}, Response: {response.text}")
                return None    

        except Exception as e:
            print(f"Error checking {file_path} in VirusTotal: {e}")

    # print("All API keys exhausted or rate limits reached.")
    return None

def scan_ip_with_virus_total(ip, api_key):
    """
    Check an IP address against VirusTotal's IP address database.

    Args:
        ip (str): IP address to check.
        api_key (str): VirusTotal API key.

    Returns:
        dict: JSON response from VirusTotal.
    """
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key}
        )
        if response.status_code == 200:
            results={}
            result = response.json()
            attributes = result.get("data", {}).get("attributes", {})
            results["country"]=attributes.get("country")
            results["asn"]=attributes.get("asn")
            results["reputation"]=attributes.get("reputation")
            results["tags"]=attributes.get("tags")
            results["whois"]=attributes.get("whois")
            last_analysis_results = attributes.get("last_analysis_results", {})
            results["last_analysis_results"]={}
            for engine, analysis in last_analysis_results.items():
                if analysis.get("result")!="clean" and analysis.get("result")!="unrated":
                    results["last_analysis_results"][engine]=analysis.get("result") 
            last_analysis_stats = attributes.get("last_analysis_stats", "N/A")
            if last_analysis_stats!="N/A":
                results["malicious"]=last_analysis_stats.get("malicious")
                results["suspicious"]=last_analysis_stats.get("suspicious")
                results["undetected"]=last_analysis_stats.get("undetected")
                results["harmless"]=last_analysis_stats.get("harmless")
                results["timeout"]=last_analysis_stats.get("timeout")
                if results["malicious"]>0 or results["suspicious"]>0:
                    results["ISmalicious"]=True
                else:
                    results["ISmalicious"]=False
            return results
                    
        elif response.status_code == 429:
            print(f"Error checking {ip} in VirusTotal: {response.text}")
            return {"error": "Rate limit reached"}
    except Exception as e:
        print(f"Error {ip} in VirusTotal: {e}")

    return None

def filter_netscan_output(netscan_json_path):
    """
    Filter the netscan JSON output to include unique owners and group connections under their respective owners.
    Stores both results in a single JSON file.

    Args:
        netscan_json_path (str): Path to the netscan output JSON file.
        output_path (str): Path to save the combined filtered JSON file.

    returns:
        dict: Combined JSON data containing unique owners and grouped connections, and a set of unique ForeignAddr.
    """
    with open(netscan_json_path, 'r') as f:
        netscan_data = json.load(f)

    # Step 1: Extract unique owners
    # Collect unique pairs of Owner and PID
    unique_owners = {(entry.get("Owner"), entry.get("PID")) for entry in netscan_data if entry.get("Owner") and entry.get("PID")}
    # Format the unique pair    s into the desired JSON structure
    unique_owners_data = [{"Owner": owner, "PID": pid} for owner, pid in unique_owners]

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
        ip=entry.get("ForeignAddr")
        if ip and ip!="*" and not re.match(r"^(::|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1]))", ip):  # Collect ForeignAddr if present
            foreign_addrs.add(ip)

    grouped_connections_data = [{"Owner": owner, "Connections": connections} 
                                for owner, connections in owner_connections.items()]

    # Combine the results
    combined_data = {
        "UniqueOwners": unique_owners_data,
        "GroupedConnections": grouped_connections_data
    }

    #return combined data and foreign addresses
    return combined_data, foreign_addrs

def filter_user_assist(userassist_json_path, output_path):
    """
    Load and filter valid entries from the userassist JSON output and save to a new file.

    Args:
        userassist_json_path (str): Path to the userassist output JSON file.
        output_path (str): Path to save the filtered JSON file.

    Returns:
        list: Filtered list of valid entries.
    """
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

    print(f"Filtered userassist data saved to {output_path}")

def find_malicious_processes():
    global vt_api_keys, vt_file_results, vt_ip_results, vt_key_use_counter, vt_key_turn, output_dir, commands
    
    _,malfind_data=run_volatility_command("malfind", commands["malfind"])
    _,pslist_data=run_volatility_command("pslist", commands["pslist"])
    
    # Dump memory for malicious processes
    dump_dir = os.path.join(output_dir, "dumped_memory")
    os.makedirs(dump_dir, exist_ok=True)

    pids_to_check=set()
    for entry in malfind_data:
        pids_to_check.add(entry.get("PID"))
        for process in pslist_data:
            if process.get("PPID") in pids_to_check and process.get("PID") not in pids_to_check:
                pids_to_check.add(process.get("PID"))
    # print("PIDs to check: ", pids_to_check)
    for pid in pids_to_check:
        pid_path = os.path.join(dump_dir, f"PID_{pid}")
        os.makedirs(pid_path, exist_ok=True)
        dump_file_paths= dump_memory(pid, pid_path) 
        if dump_file_paths:
            for path in dump_file_paths:
                result=scan_file_with_virustotal(path, vt_api_keys[vt_key_turn])
                while result=={"error": "Rate limit reached"}:
                    print("Rate limit reached for all API keys. Waiting for 15 seconds to retry.")
                    sleep(15)                        
                    result=scan_file_with_virustotal(path, vt_api_keys[vt_key_turn])
                vt_file_results.append(result)
                vt_key_use_counter+=1
                if vt_key_use_counter%4==0:
                    vt_key_turn+=1
                    vt_key_turn=vt_key_turn%len(vt_api_keys)
    with open(os.path.join(output_dir, "virustotal_results.json"), "w") as outfile:
        json.dump(vt_file_results, outfile, indent=4)
    
    check_malicious_ips(output_dir, commands, vt_api_keys, vt_key_turn, vt_key_use_counter, vt_ip_results)
        
def check_malicious_ips(output_dir, commands, vt_api_keys, vt_key_turn, vt_key_use_counter, vt_ip_results):
    """
    Run netscan, filter its output to check for malicious IPs, and display their processes.

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
    netscan_path, _ = run_volatility_command("netscan", commands["netscan"])
    combined_data, foreign_addrs = filter_netscan_output(netscan_path)
    filtered_netscan_path = os.path.join(output_dir, "filtered_netscan_with_IPcheck.json")

    for ip in foreign_addrs:
        ip_result = scan_ip_with_virus_total(ip, vt_api_keys[vt_key_turn])
        while ip_result == {"error": "Rate limit reached"}:
            print("Rate limit reached for all API keys. Waiting for 15 seconds to retry.")
            sleep(15)
            ip_result = scan_ip_with_virus_total(ip, vt_api_keys[vt_key_turn])
        vt_ip_results[ip] = ip_result
        vt_key_use_counter += 1
        if vt_key_use_counter % 4 == 0:
            vt_key_turn += 1
            vt_key_turn = vt_key_turn % len(vt_api_keys)

    for group in combined_data.get("GroupedConnections", []):
        for connection in group.get("Connections", []):
            foreign_addr = connection.get("ForeignAddr")
            pid = connection.get("pid")
            if vt_ip_results.get(foreign_addr):
                connection["VT_Results"] = vt_ip_results[foreign_addr]
                if vt_ip_results[foreign_addr]["ISmalicious"]:
                    for owner in combined_data.get("UniqueOwners", []):
                        if owner.get("PID") == pid:
                            owner["Malicious_IP"] = foreign_addr

    with open(filtered_netscan_path, "w") as outfile:
        json.dump(combined_data, outfile, indent=4)

    return filtered_netscan_path

def full_automation(memory_image, volatility_path, output_dir):
    find_malicious_processes()  
    userassist_path,_=run_volatility_command("userassist", commands["userassist"])
    filtered_userassist_path = os.path.join(output_dir, "filtered_userassist.json")
    filter_user_assist(userassist_path, filtered_userassist_path)
    run_volatility_command("wininfo", commands["wininfo"])
    run_volatility_command("cmdline", commands["cmdline"])
    
def main():
    #make variables global
    global vt_api_keys, vt_file_results, vt_ip_results, output_dir, volatility_path, memory_image, commands, vt_key_turn, vt_key_use_counter
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    print("Starting Volatility 3 Automation...")
    while True:
        print("choose the command you want to run:")
        print("1- find malicious proceesses")
        print("2- netowrk scan")
        print("3- userassist")
        print("4- full automation")
        print("5- pick a specific command")
        print("6- exit")
        choice = input("Enter your choice: ")
        if choice == "1":
            find_malicious_processes()
        elif choice == "2":
            check_malicious_ips(output_dir, commands, vt_api_keys, vt_key_turn, vt_key_use_counter, vt_ip_results)
        elif choice == "3":
            userassist_path,_=run_volatility_command("userassist", commands["userassist"])
            filtered_userassist_path = os.path.join(output_dir, "filtered_userassist.json")
            filter_user_assist(userassist_path, filtered_userassist_path)
        elif choice == "4":
            full_automation(memory_image, volatility_path, output_dir)
        elif choice == "5":
            while True:
                print("choose the command you want to run:")
                print("1- pslist")
                print("2- netscan")
                print("3- wininfo")
                print("4- userassist")
                print("5- malfind")
                print("6- cmdline")
                print("7- pastree")
                print("8- enter profile manually")
                print("9- back")
                command_choice = input("Enter your choice: ")
                if command_choice == "1":
                    run_volatility_command("pslist", commands["pslist"])
                elif command_choice == "2":
                    check_malicious_ips(output_dir, commands, vt_api_keys, vt_key_turn, vt_key_use_counter, vt_ip_results)
                elif command_choice == "3":
                    run_volatility_command("wininfo", commands["wininfo"])
                elif command_choice == "4":
                    userassist_path,_=run_volatility_command("userassist", commands["userassist"])
                    filtered_userassist_path = os.path.join(output_dir, "filtered_userassist.json")
                    filter_user_assist(userassist_path, filtered_userassist_path)
                elif command_choice == "5":
                    run_volatility_command("malfind", commands["malfind"])
                elif command_choice == "6":
                    run_volatility_command("cmdline", commands["cmdline"])
                elif command_choice == "7":
                    run_volatility_command("pastree", commands["pastree"])
                elif command_choice == "8":
                    print("Enter the command you want to run, for example: pslist.PSList, netscan.NetScan, etc.")
                    command_name = input("Enter the command name: ")
                    command = input("Enter the command: ")
                    run_volatility_command(command_name, ["python", volatility_path, "-f", memory_image, command])
                elif command_choice == "9":
                    break
                else:
                    print("Invalid choice. Please choose a valid option.")
                    continue
        elif choice == "6":
            break     
    print("Automation complete. Results are saved in the memory_analysis directory.")

if __name__ == "__main__":
    main()
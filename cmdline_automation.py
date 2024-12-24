import json
import os
import subprocess
from time import sleep
import requests
# from itertools import cycle
import hashlib
import re

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
    


def run_volatility_command(command_name, command, output_dir):
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
        return output_file
    except Exception as e:
        print(f"Error running {command_name}: {e}")
        return None


def dump_memory(pid, dump_dir, volatility_path, memory_image):
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
        return paths
    except subprocess.CalledProcessError as e:
        print(f"Failed to dump memory for PID {pid}: {e.stderr}")

    return None

def scan_file_with_virustotal(file_path, api_key, output_dir):
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
                "https://www.virustotal.com/vtapi/v2/file/report",
                params={"apikey": api_key, "resource": file_data} 
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
            elif response.status_code == 204:
                # print("Rate limit reached for current API key. Switching to the next key.")
                return {"error": "Rate limit reached"}
            else:
                print(f"Error uploading {file_path}. Status code: {response.status_code}, Response: {response.text}")
                return None    

        except Exception as e:
            print(f"Error checking {file_path} in VirusTotal: {e}")

    # print("All API keys exhausted or rate limits reached.")
    return None


def filter_netscan_output(netscan_json_path, output_path):
    """
    Filter the netscan JSON output to include unique owners and group connections under their respective owners.
    Stores both results in a single JSON file.

    Args:
        netscan_json_path (str): Path to the netscan output JSON file.
        output_path (str): Path to save the combined filtered JSON file.

    returns:
        dict: Combined JSON data containing unique owners and grouped connections.
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

    grouped_connections_data = [{"Owner": owner, "Connections": connections} 
                                for owner, connections in owner_connections.items()]

    # Combine the results
    combined_data = {
        "UniqueOwners": unique_owners_data,
        "GroupedConnections": grouped_connections_data
    }

    # Save the combined output
    with open(output_path, 'w') as outfile:
        json.dump(combined_data, outfile, indent=4)

    print(f"Combined netscan data saved to {output_path}")

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


def main():

    memory_image = "D:\\college\\GradProject\\106-RedLine\\MemoryDump.mem"
    volatility_path = "D:\\Forensics tools\\volatility3\\vol.py"

    output_dir = os.path.join(os.getcwd(), "memory_analysis")
    
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
    vt_results = []

    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    print("Starting Volatility 3 Automation...")

    # Run commands
    commands = {
        "pslist": ["python", volatility_path, "-f", memory_image, "windows.pslist.PsList"],
        # "netscan": ["python", volatility_path, "-f", memory_image, "windows.netscan.NetScan"],
        # "wininfo": ["python", volatility_path, "-f", memory_image, "windows.info.Info"],
        # "userassist": ["python", volatility_path, "-f", memory_image, "windows.registry.userassist.UserAssist"],
        "malfind": ["python", volatility_path, "-f", memory_image, "windows.malfind.Malfind"],
        # "cmdline": ["python", volatility_path, "-f", memory_image, "windows.cmdline.CmdLine"],
        # "pastree": ["python", volatility_path, "-f", memory_image, "windows.pstree.PsTree"],
    }

    output_files = {}
    for name, cmd in commands.items():
        output_files[name] = run_volatility_command(name, cmd, output_dir)

    # Process malfind output
    if output_files.get("malfind"):
        dump_dir = os.path.join(output_dir, "dumped_memory")
        os.makedirs(dump_dir, exist_ok=True)
        
        # Load malfind entries and pslist data
        malfind_json_path = output_files["malfind"]
        pslist_json_path = output_files["pslist"] if output_files.get("pslist") else None
        with open(malfind_json_path, 'r') as f:
            valid_entries = json.load(f)
        if pslist_json_path:
            with open(pslist_json_path, 'r') as f:
                pslist_data = json.load(f)
        else:
            pslist_data = []
                
        # Find the child processes of the malfinded processes
        pids_to_check=[]
        for entry in valid_entries:
            pids_to_check.append(entry.get("PID"))
            for process in pslist_data:
                if process.get("PPID") in pids_to_check and process.get("PID") not in pids_to_check:
                    pids_to_check.append(process.get("PID"))
        print("PIDS to check: ", pids_to_check)
        
        # Dump memory for the targetted processes
        for pid in pids_to_check:
            pid_path = os.path.join(dump_dir, f"PID_{pid}")
            os.makedirs(pid_path, exist_ok=True)
            dump_file_paths= dump_memory(pid, pid_path, volatility_path, memory_image) 
            if dump_file_paths:
                for path in dump_file_paths:
                    result=scan_file_with_virustotal(path, vt_api_keys[vt_key_turn] , output_dir)
                    while result=={"error": "Rate limit reached"}:
                        print("Rate limit reached for all API keys. Waiting for 15 seconds to retry.")
                        sleep(15)                        
                        result=scan_file_with_virustotal(path, vt_api_keys[vt_key_turn] , output_dir)
                    vt_results.append(result)
                    vt_key_use_counter+=1
                    if vt_key_use_counter%4==0:
                        vt_key_turn+=1
                        vt_key_turn=vt_key_turn%len(vt_api_keys)
        with open(os.path.join(output_dir, "virustotal_results.json"), "w") as outfile:
            json.dump(vt_results, outfile, indent=4)

    # Filter netscan output
    if output_files.get("netscan"):
        netscan_json_path = output_files["netscan"]
        filtered_netscan_path = os.path.join(output_dir, "filtered_netscan.json")
        filter_netscan_output(netscan_json_path, filtered_netscan_path)

    if output_files.get("userassist"):
        userassist_json_path = output_files["userassist"]
        filtered_userassist_path = os.path.join(output_dir, "filtered_userassist.json")
        filter_user_assist(userassist_json_path, filtered_userassist_path)


    print("Automation complete. Results are saved in the memory_analysis directory.")

if __name__ == "__main__":
    main()
import json
import os
import subprocess
import requests
from itertools import cycle

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

        headers = output_lines[2].split()
        data = []
        for line in output_lines[3:]:
            values = line.split()
            entry = dict(zip(headers, values))
            if entry != {}:
                data.append(entry)

        with open(output_file, "w") as outfile:
            json.dump(data, outfile, indent=4)

        print(f"Output saved to {output_file}")
        return output_file
    except Exception as e:
        print(f"Error running {command_name}: {e}")
        return None

def load_malfind_entries(malfind_json_path, output_path):
    """
    Load and filter valid entries from the malfind JSON output and save to a new file.

    Args:
        malfind_json_path (str): Path to the malfind output JSON file.
        output_path (str): Path to save the filtered JSON file.

    Returns:
        list: Filtered list of valid entries.
    """
    with open(malfind_json_path, 'r') as f:
        malfind_data = json.load(f)

    valid_entries = []
    for entry in malfind_data:
        pid = entry.get("PID")
        process_name = entry.get("Process")
        start_address = entry.get("Start")

        # Validate entry
        if pid and pid.isdigit() and process_name and start_address and start_address.startswith("0x"):
            valid_entries.append(entry)

    # Save filtered entries to a new JSON file
    with open(output_path, 'w') as outfile:
        json.dump(valid_entries, outfile, indent=4)

    print(f"Filtered malfind data saved to {output_path}")
    return valid_entries


def dump_memory(entry, dump_dir, volatility_path, memory_image):
    """
    Dump memory for a given entry using Volatility.

    Args:
        entry (dict): A valid malfind entry.
        dump_dir (str): Directory to save dumped memory files.
        volatility_path (str): Path to the Volatility3 script.
        memory_image (str): Path to the memory image.

    Returns:
        str: Path to the dumped .exe file, or None if dumping fails.
    """
    pid = entry.get("PID")

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
        for file_name in os.listdir(dump_dir):
            if file_name.endswith(".exe.img") or file_name.endswith(".dll.img"):
                print(os.path.join(dump_dir, file_name))
                return os.path.join(dump_dir, file_name)

    except subprocess.CalledProcessError as e:
        print(f"Failed to dump memory for PID {pid}: {e.stderr}")

    return None

def scan_file_with_virustotal(file_path, api_keys):
    """
    Upload a file to VirusTotal for scanning and return the result as JSON.

    Args:
        file_path (str): Path to the file to be uploaded.
        api_keys (list): List of VirusTotal API keys.

    Returns:
        dict: JSON response from VirusTotal.
    """
    api_cycle = cycle(api_keys)
    for _ in range(len(api_keys) * 4):  # 4 requests per key
        api_key = next(api_cycle)
        with open(file_path, 'rb') as file:
            try:
                response = requests.post(
                    "https://www.virustotal.com/api/v3/files",
                    headers={"x-apikey": api_key},
                    files={"file": file}
                )
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 429:
                    print("Rate limit reached for current API key. Switching to the next key.")
                    continue
                else:
                    print(f"Error uploading {file_path}. Status code: {response.status_code}, Response: {response.text}")
            except Exception as e:
                print(f"Error uploading {file_path} to VirusTotal: {e}")
                continue

    print("All API keys exhausted or rate limits reached.")
    return None

def filter_netscan_output(netscan_json_path, output_path):
    """
    Filter the netscan JSON output to include only unique owners.

    Args:
        netscan_json_path (str): Path to the netscan output JSON file.
        output_path (str): Path to save the filtered JSON file.
    """
    with open(netscan_json_path, 'r') as f:
        netscan_data = json.load(f)

    unique_owners = {entry.get("Owner") for entry in netscan_data if entry.get("Owner")}
    filtered_data = [{"Owner": owner} for owner in unique_owners]

    with open(output_path, 'w') as outfile:
        json.dump(filtered_data, outfile, indent=4)

    print(f"Filtered netscan data with unique owners saved to {output_path}")

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
    memory_image = "D:\\Graduation project\\memdump\\192-Reveal.dmp"
    volatility_path = "D:\\Graduation project\\volatility3\\vol.py"

    output_dir = os.path.join(os.getcwd(), "memory_analysis")
    vt_api_keys = ["api_key_1", "api_key_2", "api_key_3", "api_key_4", "api_key_5",
                   "api_key_6", "api_key_7", "api_key_8", "api_key_9", "api_key_10",
                   "api_key_11", "api_key_12", "api_key_13", "api_key_14", "api_key_15"]

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    print("Starting Volatility 3 Automation...")

    # Run commands
    commands = {
        "pslist": ["python", volatility_path, "-f", memory_image, "windows.pslist.PsList"],
        "netscan": ["python", volatility_path, "-f", memory_image, "windows.netscan.NetScan"],
        "wininfo": ["python", volatility_path, "-f", memory_image, "windows.info.Info"],
        "userassist": ["python", volatility_path, "-f", memory_image, "windows.registry.userassist.UserAssist"],
        "malfind": ["python", volatility_path, "-f", memory_image, "windows.malfind.Malfind"],
    }

    output_files = {}
    for name, cmd in commands.items():
        output_files[name] = run_volatility_command(name, cmd, output_dir)

    # Process malfind output
    if output_files.get("malfind"):
        malfind_json_path = output_files["malfind"]
        filtered_malfind_path = os.path.join(output_dir, "filtered_malfind.json")
        valid_entries = load_malfind_entries(malfind_json_path, filtered_malfind_path)
        dump_dir = os.path.join(output_dir, "dumped_memory")
        print("dump_dir: ", dump_dir)
        os.makedirs(dump_dir, exist_ok=True)

        for entry in valid_entries:
            pid=entry.get("PID")
            pid_path = os.path.join(dump_dir, f"PID_{pid}")
            os.makedirs(pid_path, exist_ok=True)
            dump_memory(entry, pid_path, volatility_path, memory_image) #capture el output hna ya negm, enta bt3ml return ll path bta3 el exe file el dumped
            # Uncomment to enable VirusTotal scanning
            # if dump_file_path and dump_file_path.endswith(".exe"):
            #     scan_file_with_virustotal(dump_file_path, vt_api_keys)

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
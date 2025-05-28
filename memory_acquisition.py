import os
import sys
import json
import ctypes
import logging
import subprocess
from tkinter import Tk, filedialog, Listbox, Button, MULTIPLE, Frame, Scrollbar, RIGHT, Y, LEFT, BOTH, END
import uuid

def parse_processes(lines):
    processes=[]
    for line in lines:
        # Remove quotes and split by comma
        parts = line.strip('"').split('","')
        if len(parts) >= 2:
            name = parts[0]
            try:
                pid = int(parts[1])
                processes.append((pid, name))
            except ValueError:
                continue
    # sort processes by PID
    processes.sort(key=lambda x: x[0])
    return processes

def select_processes_gui(processes):
    """
    Opens a GUI that allows selecting multiple processes from a list.
    Returns a list of selected PIDs.
    """
    selected_pids = []
    
    def on_submit():
        nonlocal selected_pids
        indices = process_listbox.curselection()
        selected_pids = [processes[i][0] for i in indices]
        root.destroy()
    
    root = Tk()
    root.title("Select Processes to Dump")
    root.geometry("500x400")
    
    root.attributes("-topmost", True)
    frame = Frame(root)
    frame.pack(fill=BOTH, expand=True, padx=10, pady=10)
    
    scrollbar = Scrollbar(frame)
    scrollbar.pack(side=RIGHT, fill=Y)
    
    process_listbox = Listbox(frame, selectmode=MULTIPLE, yscrollcommand=scrollbar.set)
    process_listbox.pack(side=LEFT, fill=BOTH, expand=True)
    
    scrollbar.config(command=process_listbox.yview)
    
    for pid, name in processes:
        process_listbox.insert(END, f"{pid}: {name}")

    submit_button = Button(root, text="Dump Selected Processes", command=on_submit)
    submit_button.pack(pady=10)
    
    root.mainloop()
    return selected_pids

def dump_specific_processes(pids, output_dir):
    """
    Uses procdump to dump memory of specific processes by PID.
    Returns a list of paths to the created dump files.
    """
    dump_files = []
    
    try:
        # Ensure procdump is available
        procdump_path = "procdump.exe"
        if not os.path.exists(procdump_path):
            logging.error("procdump.exe not found in the current directory")
            return []
        
        os.makedirs(output_dir, exist_ok=True)
        
        for pid in pids:
            output_file = os.path.join(output_dir, f"process_{pid}_dump.dmp")
            # Run procdump to dump the process memory
            logging.info(f"Dumping process {pid} to {output_file} using procdump...")

            subprocess.run([procdump_path, "-accepteula", "-ma", str(pid), output_file], check=True)
            dump_files.append(output_file)
            logging.info(f"Successfully dumped process {pid} to {output_file}")
    
    except subprocess.CalledProcessError as e:
        logging.error(f"Error dumping processes: {e}")
    
    return dump_files

def acquire_memory_paths():
    """
    Handles memory acquisition based on user choices:
    1) Local or remote acquisition
    2) For local: existing dump, full memory dump, or specific processes
    3) For remote: full memory dump or specific processes
    
    Returns:
        memory_image (str or list): Path to memory dump file or list of process dump files
        is_process_dump (bool): Whether the memory image is a process dump
    """
    memory_image = None
    is_process_dump = False
    
    print("\nMemory Acquisition:")
    print("1) Local acquisition")
    print("2) Remote acquisition")
    print("3) Exit")
    
    location_choice = input("Choose acquisition location (1/2/3): ").strip()
    
    if location_choice == "1":
        local_choice = ""
        while local_choice not in ["1", "2", "3", "4"]:
            # Local acquisition
            print("\nLocal Acquisition Options:")
            print("1) Use existing memory dump file")
            print("2) Perform live full memory dump")
            print("3) Dump specific processes")
            print("4) Back")
            local_choice = input("Choose local acquisition method (1/2/3/4): ").strip()
            if local_choice == "4":
                return "back", False
            if local_choice not in ["1", "2", "3"]:
                logging.warning("Invalid local acquisition choice.")
                continue
            
        
        if local_choice == "1":
            # Use existing dump file
            logging.info("User chose to use existing memory dump file.")
            temp_root = Tk()
            temp_root.attributes("-topmost", True)
            temp_root.withdraw()
            memory_image = filedialog.askopenfilename(
                parent=temp_root,
                title="Select Memory Dump File",
                filetypes=[("Memory Dump Files", "*.mem;*.raw;*.dmp"), ("All Files", "*.*")]
            )
            temp_root.destroy()
            
            if not memory_image:
                logging.warning("No memory dump file selected.")
                return None, False
            logging.info(f"Memory dump file selected: {memory_image}")
            
        elif local_choice == "2":
            # Live full memory dump
            try:
                is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception as e:
                is_admin = False
                logging.error(f"Error checking admin privileges: {e}")
            
            if not is_admin:
                consent = input("Live acquisition requires admin privileges. Proceed? (y/n): ").lower()
                if consent == "y":
                    logging.info("Re-running script as admin for live acquisition.")
                    ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", sys.executable, " ".join(sys.argv), None, 1
                    )
                    sys.exit(0)
                else:
                    logging.info("Live acquisition canceled by user.")
                    return None, False
            
            logging.info("Acquiring live memory image with winpmem...")
            local_winpmem_path = r"winpmem_mini_x64_rc2.exe"
            acquired_file = os.path.join(os.getcwd(), "live_memory_dump.mem")
            
            try:
                subprocess.run([local_winpmem_path, acquired_file], check=True)
                memory_image = acquired_file
                logging.info(f"Live memory acquired and saved to {acquired_file}.")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to acquire live memory: {e}")
                return None, False
                
        elif local_choice == "3":
            try:
                is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception as e:
                is_admin = False
                logging.error(f"Error checking admin privileges: {e}")
            
            if not is_admin:
                consent = input("Live acquisition requires admin privileges. Proceed? (y/n): ").lower()
                if consent == "y":
                    logging.info("Re-running script as admin for live acquisition.")
                    ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", sys.executable, " ".join(sys.argv), None, 1
                    )
                    sys.exit(0)
                else:
                    logging.info("Live acquisition canceled by user.")
                    return None, False
            
            # Dump specific processes
            logging.info("Listing running processes...")
            try:
                result = subprocess.run(["tasklist", "/FO", "CSV"], capture_output=True, text=True, check=True)
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                processes= parse_processes(lines)
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to list processes: {e}")
                return []
            
            if not processes:
                logging.error("Failed to retrieve the list of running processes.")
                return None, False
            
            print("\nProcesses:")
            for i, (pid, name) in enumerate(processes):
                print(f"{i+1}) PID {pid}: {name}")
            
            selected_indices = input("Enter process numbers to dump (comma-separated): ").strip()
            selected_indices = [int(idx.strip()) for idx in selected_indices.split(",") if idx.strip().isdigit()]
            
            if not selected_indices:
                logging.warning("No processes selected for dumping.")
                return None, False

            selected_pids = [processes[i-1][0] for i in selected_indices if i-1 < len(processes)]
            
            if not selected_pids:
                logging.warning("No valid processes selected for dumping.")
                return None, False
            
            logging.info(f"Selected PIDs for dumping: {selected_pids}")
            output_dir = os.path.join(os.getcwd(), "process_dumps")
            dump_files = dump_specific_processes(selected_pids, output_dir)
            
            if not dump_files:
                logging.error("Failed to dump any processes.")
                return None, False
                
            memory_image = dump_files
            is_process_dump = True
            logging.info(f"Successfully dumped {len(dump_files)} processes.")
            
        elif local_choice == "4":
            logging.info("User went back from local acquisition options.")
            return None, False
            
        else:
            logging.warning("Invalid local acquisition choice.")
            return None, False
            
    elif location_choice == "2":
        remote_choice = ""
        while remote_choice not in ["1", "2", "3"]:
            # Remote acquisition
            print("\nRemote Acquisition Options:")
            print("1) Full memory dump")
            print("2) Dump specific processes")
            print("3) Back")
            remote_choice = input("Choose remote acquisition method (1/2/3): ").strip()
        if remote_choice == "3":
            return "back", False  # User chose to go back
        
        # Get remote machine details
        logging.info("Gathering remote machine details for acquisition.")
        print("Please provide the following details for the remote machine:")
        remote_ip = input("Enter remote machine IP address (e.g. 192.168.112.146): ").strip()
        remote_domain = input("Enter domain for remote machine (e.g. RACOONS): ").strip()
        remote_user = input("Enter username for remote machine (e.g. Administrator): ").strip()
        remote_password = input("Enter password for remote machine: ").strip()
                
        if remote_choice == "1":
            # Full memory dump (using winpmem)
            local_winpmem_path = r"winpmem_mini_x64_rc2.exe"
            if not os.path.isfile(local_winpmem_path):
                logging.error(f"Local winpmem not found at {local_winpmem_path}. Adjust path as necessary.")
                return None, False
            
            # Generate a random folder name under the user's temp (to avoid collisions)
            random_folder_name = f"mem_acq_{uuid.uuid4().hex[:8]}"
            
            # The base Temp folder for the user
            base_temp = f"C:\\Users\\{remote_user}\\AppData\\Local\\Temp"
            remote_acq_dir = os.path.join(base_temp, random_folder_name)
            
            # Build the remote paths
            remote_winpmem_path = os.path.join(remote_acq_dir, os.path.basename(local_winpmem_path))
            remote_dump_path = os.path.join(remote_acq_dir, "remote_live_memory_dump.mem")
            
            # Local dump path
            local_dump_path = os.path.join(os.getcwd(), "remote_live_memory_dump.mem")
            
            # For file copying, we'll use net use + xcopy + PsExec
            remote_share = f"\\\\{remote_ip}\\C$"
            remote_share_acq_dir = f"\\\\{remote_ip}\\C$\\Users\\{remote_user}\\AppData\\Local\\Temp\\{random_folder_name}"
            remote_share_dump_file = os.path.join(remote_share_acq_dir, "remote_live_memory_dump.mem")
            
            try:
                # 1) Map the remote machine's C$ share using net use
                logging.info(f"Establishing connection to {remote_share} using net use...")
                print("1) Mapping remote share...")
                subprocess.run([
                    "net", "use", remote_share, remote_password, f"/user:{remote_user}"
                ], check=True)
                
                # 2) Create our dedicated subfolder in the remote user's temp
                logging.info(f"Creating dedicated subfolder: {remote_acq_dir}")
                print("2) Creating dedicated subfolder...")
                subprocess.run([
                    "PsExec.exe",
                    "-accepteula",          # auto‑accept the EULA
                    f"\\\\{remote_ip}",
                    "-u", f"{remote_domain}\\{remote_user}",
                    "-p", remote_password,
                    "-h",
                    "cmd", "/c",
                    "mkdir", remote_acq_dir
                ], check=True)
                
                # 3) Copy winpmem to that subfolder
                logging.info(f"Copying {local_winpmem_path} to {remote_winpmem_path} via xcopy...")
                print("3) Copying winpmem to remote subfolder...")
                subprocess.run([
                    "xcopy",
                    local_winpmem_path,
                    remote_share_acq_dir + "\\",
                    "/Y"  # Overwrite existing
                ], check=True)
                
                # 4) Run winpmem with PsExec to dump memory into that subfolder
                logging.info("Running winpmem on remote host to dump memory.")
                print("4) Running winpmem on remote host...")
                subprocess.run([
                    "PsExec.exe",
                    "-accepteula", 
                    f"\\\\{remote_ip}",
                    "-s",                   # run as SYSTEM
                    "-u", f"{remote_domain}\\{remote_user}",
                    "-p", remote_password,
                    remote_winpmem_path,
                    remote_dump_path,
                ], check=False)
                
                # 5) Copy the resulting memory dump back locally
                logging.info(f"Copying remote memory dump from {remote_share_dump_file} to {local_dump_path}...")
                print("5) Copying remote memory dump back to local machine...")
                subprocess.run([
                    "xcopy",
                    remote_share_dump_file,
                    local_dump_path,
                    "/Y"
                ], check=True)
                
                memory_image = local_dump_path
                logging.info(f"Remote memory dump successfully copied to {local_dump_path}.")
                
            except subprocess.CalledProcessError as e:
                logging.error(f"Error during remote acquisition steps: {e}")
                return None, False
                
            finally:
                # 6) Clean up the entire subfolder and contents
                logging.info(f"Cleaning up subfolder: {remote_acq_dir}")
                print("6) Cleaning up remote subfolder...")
                try:
                    subprocess.run([
                        "PsExec.exe",
                        "-accepteula",          # auto‑accept the EULA
                        f"\\\\{remote_ip}",
                        "-u", f"{remote_domain}\\{remote_user}",
                        "-p", remote_password,
                        "-h",
                        "cmd", "/c",
                        f"rmdir /S /Q {remote_acq_dir}"
                    ], check=True)
                except subprocess.CalledProcessError as e:
                    logging.warning(f"Cleanup step failed: {e}")
                
                # Disconnect from remote share
                logging.info(f"Disconnecting from {remote_share}")
                subprocess.run(["net", "use", remote_share, "/delete"], check=True)
        
        elif remote_choice == "2":
            # Remote process dump
            # Map network drive
            remote_share = f"\\\\{remote_ip}\\C$"
            try:
                # Connect to remote share
                logging.info(f"Establishing connection to {remote_share} using net use...")
                print("1) Mapping remote share...")
                subprocess.run([
                    "net", "use", remote_share, remote_password, f"/user:{remote_user}"
                ], check=True)
                
                # Create a temp directory for our work
                random_folder_name = f"proc_dump_{uuid.uuid4().hex[:8]}"
                base_temp = f"C:\\Users\\{remote_user}\\AppData\\Local\\Temp"
                remote_acq_dir = os.path.join(base_temp, random_folder_name)
                remote_share_acq_dir = f"\\\\{remote_ip}\\C$\\Users\\{remote_user}\\AppData\\Local\\Temp\\{random_folder_name}"
                
                # Create directory on remote machine
                logging.info(f"Creating dedicated subfolder: {remote_acq_dir}")
                print("2) Creating dedicated subfolder...")
                subprocess.run([
                    "PsExec.exe",
                    f"\\\\{remote_ip}",
                    "-accepteula",          # auto‑accept the EULA
                    "-u", f"{remote_domain}\\{remote_user}",
                    "-p", remote_password,
                    "-h",
                    "cmd", "/c",
                    "mkdir", remote_acq_dir
                ], check=True)
                
                # Copy procdump to remote machine
                local_procdump_path = r"procdump.exe"
                if not os.path.isfile(local_procdump_path):
                    logging.error(f"Local procdump not found at {local_procdump_path}. Adjust path as necessary.")
                    return None, False
                
                logging.info(f"Copying {local_procdump_path} to remote machine...")
                print("3) Copying procdump to remote machine...")
                subprocess.run([
                    "xcopy",
                    local_procdump_path,
                    remote_share_acq_dir + "\\",
                    "/Y"
                ], check=True)
                
                # Get list of processes on remote machine
                logging.info("Getting list of processes on remote machine...")
                print("4) Listing processes on remote machine...")
                result = subprocess.run([
                    "PsExec.exe",
                    f"\\\\{remote_ip}",
                    "-accepteula",          # auto‑accept the EULA
                    "-u", f"{remote_domain}\\{remote_user}",
                    "-p", remote_password,
                    "-h",
                    "tasklist", "/FO", "CSV"
                ], capture_output=True, text=True, check=True)
                
                # Parse the process list
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                remote_processes = parse_processes(lines)
                
                
                # Display the process list and let user select
                print("\nRemote Processes:")
                for i, (pid, name) in enumerate(remote_processes):
                    print(f"{i+1}) PID {pid}: {name}")
                
                selected_indices = input("Enter process numbers to dump (comma-separated): ").strip()
                selected_indices = [int(idx.strip()) for idx in selected_indices.split(",") if idx.strip().isdigit()]
                
                if not selected_indices:
                    logging.warning("No processes selected for dumping.")
                    return None, False
                
                selected_pids = [remote_processes[i-1][0] for i in selected_indices if i-1 < len(remote_processes)]
                
                if not selected_pids:
                    logging.warning("No valid processes selected for dumping.")
                    return None, False
                
                logging.info(f"Selected PIDs for dumping: {selected_pids}")
                print(f"5) Dumping {len(selected_pids)} selected processes...")
                
                # Dump each selected process on the remote machine
                remote_procdump_path = os.path.join(remote_acq_dir, "procdump.exe")
                remote_dump_files = []
                local_dump_files = []
                
                for pid in selected_pids:
                    remote_output_file = os.path.join(remote_acq_dir, f"process_{pid}_dump.dmp")
                    remote_dump_files.append(remote_output_file)

                    logging.info(f"Dumping remote process {pid}...")
                    subprocess.run([
                        "PsExec.exe",
                        "-accepteula",          # auto‑accept the EULA
                        f"\\\\{remote_ip}",
                        "-u", f"{remote_domain}\\{remote_user}",
                        "-p", remote_password,
                        "-h",
                        remote_procdump_path,
                        "-accepteula",
                        "-ma", str(pid),
                        remote_output_file
                    ], check=False)  # Don't check=True as procdump might return non-zero even on success
                
                # Create local directory for process dumps
                local_output_dir = os.path.join(os.getcwd(), "remote_process_dumps")
                os.makedirs(local_output_dir, exist_ok=True)
                
                # Copy each dump file back to local machine
                print("6) Copying process dumps back to local machine...")
                for remote_file in remote_dump_files:
                    remote_share_path = remote_file.replace(f"C:\\", f"\\\\{remote_ip}\\C$\\")
                    local_file = os.path.join(local_output_dir, os.path.basename(remote_file))
                    
                    try:
                        logging.info(f"Copying {remote_share_path} to {local_file}...")
                        subprocess.run([
                            "xcopy",
                            remote_share_path,
                            local_file,
                            "/Y",
                            "/-I" 
                        ], check=True)
                        local_dump_files.append(local_file)
                    except subprocess.CalledProcessError as e:
                        logging.warning(f"Failed to copy process dump: {e}")
                
                memory_image = local_dump_files
                is_process_dump = True
                logging.info(f"Successfully copied {len(local_dump_files)} process dumps.")
                
                # Clean up remote resources
                print("7) Cleaning up remote resources...")
                try:
                    subprocess.run([
                        "PsExec.exe",
                        "-accepteula",          # auto‑accept the EULA
                        f"\\\\{remote_ip}",
                        "-u", f"{remote_domain}\\{remote_user}",
                        "-p", remote_password,
                        "-h",
                        "cmd", "/c",
                        f"rmdir /S /Q {remote_acq_dir}"
                    ], check=True)
                except subprocess.CalledProcessError as e:
                    logging.warning(f"Cleanup step failed: {e}")
                
                # Disconnect from remote share
                logging.info(f"Disconnecting from {remote_share}")
                subprocess.run(["net", "use", remote_share, "/delete"], check=True)
                
            except subprocess.CalledProcessError as e:
                logging.error(f"Error during remote process dump: {e}")
                return None, False
        
        
        else:
            logging.warning("Invalid remote acquisition choice.")
            return None, False
    
    elif location_choice == "3":
        logging.info("Exiting memory acquisition.")
        sys.exit(0)
    
    else:
        logging.warning("Invalid acquisition location choice.")
        return None, False
    
    return memory_image, is_process_dump

def get_volatility_path():
    """
    Prompts the user to select a Volatility Python script.
    Returns the path to the selected script.
    """
    logging.info("Prompting user to select Volatility script path.")
    temp_root = Tk()
    temp_root.attributes("-topmost", True)
    temp_root.withdraw()
    volatility_path = filedialog.askopenfilename(
        title="Select Volatility Python Script",
        filetypes=[("Python Files", "*.py"), ("All Files", "*.*")]
    )
    temp_root.destroy()
    
    if not volatility_path:
        logging.warning("No Volatility script selected.")
        return None
    
    logging.info(f"Volatility script selected: {volatility_path}")
    return volatility_path

def acquire_memory_and_volatility_paths():
    """
    Main function that handles the memory acquisition and volatility path selection process.
    This function has been updated to separate the acquisition and volatility selection.
    
    Returns:
        memory_image (str or list): Path to memory dump file or list of process dump files
        volatility_path (str): Path to the selected Volatility script
        is_process_dump (bool): Whether the memory image is a process dump
    """
    # Acquire memory image(s)
    memory_image="back"
    while memory_image=="back":
        memory_image, is_process_dump = acquire_memory_paths()
        
    if not memory_image:
        logging.error("Memory acquisition failed or was cancelled.")
        return None, None, False
    
    # Get volatility path
    volatility_path = get_volatility_path()
    
    if not volatility_path:
        logging.error("Volatility path selection failed or was cancelled.")
        return memory_image, None, is_process_dump
    
    return memory_image, volatility_path, is_process_dump

def load_vt_api_keys():
    """
    Loads VirusTotal API keys from vt_accounts.json (expected in current directory).
    Returns:
        List of API keys (list of str)
    """
    vt_api_keys = []
    try:
        with open("vt_accounts.json", "r") as f:
            vt_accounts = json.load(f)
        for entry in vt_accounts:
            api_key = entry.get("APIKEY")
            if api_key:
                vt_api_keys.append(api_key)
        logging.info(f"Loaded {len(vt_api_keys)} VirusTotal API keys.")
    except Exception as e:
        logging.error(f"Error loading VirusTotal API keys: {e}")
        sys.exit(1)
    return vt_api_keys
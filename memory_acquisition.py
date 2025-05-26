import os
import sys
import json
import ctypes
import logging
import subprocess
from tkinter import Tk, filedialog
import uuid

def acquire_memory_and_volatility_paths(vt_api_keys):
    """
    Asks the user how they want to acquire the memory dump:
    1) Live (local)
    2) Manual (pick .mem file)
    3) Remote (using PsExec and net use)

    The remote acquisition flow is:
    1) Prompt IP, username, and password for the remote machine.
    2) Parse the username to derive the short username portion (if provided in DOMAIN\\user form).
    3) Create a dedicated subfolder in C:\\Users\\<shortUser>\\AppData\\Local\\Temp to store
        winpmem, the memory dump, and any other artifacts.
    4) Copy local winpmem to that subfolder.
    5) Run winpmem remotely via PsExec, dumping memory to that subfolder.
    6) Copy the memory dump back to this local machine.
    7) Delete the subfolder and all its contents on the remote machine to clean up.
    8) Disconnect the remote share.

    Returns:
        memory_image (str): Path to the acquired/selected memory dump file
        volatility_path (str): Path to the selected Volatility (.py) script
    """

    # def parse_username(user_str):
    #     """
    #     Extracts just the username from 'DOMAIN\\Username' or returns user_str if there's no backslash.
    #     E.g. 'RACOONS\\Administrator' -> 'Administrator'
    #     """
    #     if "\\" in user_str:
    #         return user_str.rsplit("\\", 1)[-1]
    #     return user_str

    memory_image = None
    volatility_path = None

    while not memory_image or not volatility_path:
        print("\nMemory acquisition:")
        print("1) Live acquisition (local)")
        print("2) Manual selection (pick .mem file)")
        print("3) Remote acquisition (using PsExec and net use)")
        print("4) Exit")

        choice = input("Choose (1/2/3/4): ").strip()

        if choice == "1":
            # Live acquisition on local machine
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
                    sys.exit(0)

            logging.info("Acquiring live memory image with winpmem...")
            local_winpmem_path = r"winpmem_mini_x64_rc2.exe"  # Adjust as needed
            acquired_file = os.path.join(os.getcwd(), "live_memory_dump.mem")

            try:
                subprocess.run([local_winpmem_path, acquired_file], check=True)
                memory_image = acquired_file
                logging.info(f"Live memory acquired and saved to {acquired_file}.")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to acquire live memory: {e}")
                sys.exit(1)

        elif choice == "2":
            # Manual selection of an existing dump file
            logging.info("User chose manual selection of memory dump file.")
            temp_root = Tk()
            temp_root.attributes("-topmost", True)
            temp_root.withdraw()
            memory_image = filedialog.askopenfilename(
                parent=temp_root,
                title="Select Memory Dump File",
                filetypes=[("Memory Dump Files", "*.mem"), ("All Files", "*.*")]
            )
            temp_root.destroy()

            if not memory_image:
                logging.warning("No memory dump file selected. Please try again.")
                continue
            else:
                logging.info(f"Memory dump file selected: {memory_image}")

        elif choice == "3":
            # Remote acquisition
            logging.info("User chose remote acquisition of memory dump.")
            remote_ip = input("Enter remote machine IP address (e.g. 192.168.112.146): ").strip()
            remote_domain = input("Enter domain for remote machine (e.g. RACOONS): ").strip()
            remote_user = input("Enter username for remote machine (e.g. Administrator): ").strip()
            remote_password = input("Enter password for remote machine: ").strip()

            # short_user = parse_username(remote_user)

            # Local path to winpmem that we want to send to the remote machine
            local_winpmem_path = r"winpmem_mini_x64_rc2.exe"
            if not os.path.isfile(local_winpmem_path):
                logging.error(f"Local winpmem not found at {local_winpmem_path}. Adjust path as necessary.")
                sys.exit(1)

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

            # 1) Map the remote machine's C$ share using net use
            try:
                logging.info(f"Establishing connection to {remote_share} using net use...")
                print("1) Mapping remote share...")
                subprocess.run([
                    "net", "use", remote_share, remote_password, f"/user:{remote_user}"
                ], check=True)
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to map remote share: {e}")
                sys.exit(1)

            try:
                # 2) Create our dedicated subfolder in the remote user's temp
                logging.info(f"Creating dedicated subfolder: {remote_acq_dir}")
                print("2) Creating dedicated subfolder...")
                subprocess.run([
                    "PsExec.exe",
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
                    f"\\\\{remote_ip}",
                    "-accepteula",          # auto‑accept the EULA
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
                sys.exit(1)

            finally:
                # 6) Clean up the entire subfolder and contents
                logging.info(f"Cleaning up subfolder: {remote_acq_dir}")
                print("6) Cleaning up remote subfolder...")
                try:
                    subprocess.run([
                        "PsExec.exe",
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

        elif choice == "4":
            logging.info("Exiting memory acquisition.")
            sys.exit(0)

        else:
            logging.warning("Invalid choice for memory acquisition.")
            continue

        # Prompt user for Volatility script path
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
            logging.warning("No Volatility script selected. Please try again.")
            continue
        else:
            logging.info(f"Volatility script selected: {volatility_path}")

    return memory_image, volatility_path

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
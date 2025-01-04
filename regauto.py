import subprocess
import os
import json
from regipy.registry import RegistryHive
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox, Listbox, MULTIPLE

# GUI for hive selection

def select_hives(hives):
    root = tk.Tk()
    root.withdraw()  # Hide the root window

    selected_hives = []

    def on_select():
        nonlocal selected_hives
        selected_hives = [listbox.get(idx) for idx in listbox.curselection()]
        root.destroy()

    root.deiconify()
    root.title("Select Registry Hives")
    root.geometry("300x400")

    listbox = Listbox(root, selectmode=MULTIPLE)
    for hive in hives:
        listbox.insert(tk.END, hive)
    listbox.pack(pady=20)

    select_button = tk.Button(root, text="Select", command=on_select)
    select_button.pack()

    root.mainloop()
    return selected_hives

# GUI for selecting files

def select_files():
    root = tk.Tk()
    root.withdraw()
    file_paths = filedialog.askopenfilenames(title="Select Registry Hives")
    return file_paths

# Acquire all critical registry hives and related files

def acquire_registry_hives():
    rawcopy_path = r"C:\Users\Hasan\Desktop\regipy\RawCopy.exe"
    output_dir = r"C:\Users\Hasan\Desktop\regipy\output"
    os.makedirs(output_dir, exist_ok=True)

    username = input("Enter the username to acquire NTUSER.DAT and UsrClass.dat for: ")

    system_hives = [
        ("SYSTEM", r"C:\Windows\System32\config\SYSTEM"),
        ("SYSTEM.LOG1", r"C:\Windows\System32\config\SYSTEM.LOG1"),
        ("SYSTEM.LOG2", r"C:\Windows\System32\config\SYSTEM.LOG2"),

        ("SOFTWARE", r"C:\Windows\System32\config\SOFTWARE"),
        ("SOFTWARE.LOG1", r"C:\Windows\System32\config\SOFTWARE.LOG1"),
        ("SOFTWARE.LOG2", r"C:\Windows\System32\config\SOFTWARE.LOG2"),

        ("SAM", r"C:\Windows\System32\config\SAM"),
        ("SAM.LOG1", r"C:\Windows\System32\config\SAM.LOG1"),
        ("SAM.LOG2", r"C:\Windows\System32\config\SAM.LOG2"),

        ("SECURITY", r"C:\Windows\System32\config\SECURITY"),
        ("SECURITY.LOG1", r"C:\Windows\System32\config\SECURITY.LOG1"),
        ("SECURITY.LOG2", r"C:\Windows\System32\config\SECURITY.LOG2"),

        ("NTUSER.DAT", rf"C:\Users\{username}\NTUSER.DAT"),
        ("NTUSER.LOG1", rf"C:\Users\{username}\NTUSER.DAT.LOG1"),
        ("NTUSER.LOG2", rf"C:\Users\{username}\NTUSER.DAT.LOG2"),

        ("Amcache.hve", r"C:\Windows\appcompat\Programs\Amcache.hve"),
        ("Amcache.hve.LOG1", r"C:\Windows\appcompat\Programs\Amcache.hve.LOG1"),
        ("Amcache.hve.LOG2", r"C:\Windows\appcompat\Programs\Amcache.hve.LOG2"),
      
        ("UsrClass.dat", rf"C:\Users\{username}\AppData\Local\Microsoft\Windows\UsrClass.dat"),
        ("UsrClass.LOG1", rf"C:\Users\{username}\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG1"),
        ("UsrClass.LOG2", rf"C:\Users\{username}\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG2"),

        ("CLASSES_ROOT_HIVE_TYPE", r"C:\Windows\System32\config\CLASSES"),
        ("BCD_HIVE_TYPE", r"C:\Windows\System32\config\BCD"),

    ]

    selected_hives = select_hives([hive[0] for hive in system_hives])

    for hive_name, hive_path in system_hives:
        if hive_name in selected_hives:
            command = f'{rawcopy_path} /FileNamePath:"{hive_path}" /OutputPath:"{output_dir}"'
            print(f"Acquiring {hive_name} hive...")
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"[+] {hive_name} acquired successfully! Saved at: {output_dir}")
            else:
                print(f"[-] Failed to acquire {hive_name}: {result.stderr}")

def parse_hive_header():
    hives = select_files()
    for hive in hives:
        command = f'regipy-parse-header "{hive}"'
        print(f"Parsing header for {hive}...")
        subprocess.run(command, shell=True)
        print(f"[+] {hive} Header parsed successfully!.")

def analyze_registry_hive():
    input_dir = r"C:\Users\Hasan\Desktop\regipy\output"
    analysis_dir = r"C:\Users\Hasan\Desktop\regipy\analysis"
    os.makedirs(analysis_dir, exist_ok=True)

    hives = ["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "NTUSER.DAT", "UsrClass.dat", "Amcache.hve"]
    selected_hives = select_hives(hives)
    
    for hive in selected_hives:
        command = f'regipy-plugins-run {input_dir}\{hive} -o {analysis_dir}\{hive}.json'
        print(f"Analysing {hive} hive...")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[+] {hive} Analysed successfully! Saved at: {analysis_dir}")
        else:
            print(f"[-] Failed to Analyse {hive}: {result.stderr}")

def compare_registry_hives():
    output_dir = r"C:\Users\Hasan\Desktop\regipy\output"
    hives = select_files()
    if len(hives) == 2:
        command = f'regipy-diff "{hives[0]}" "{hives[1]}" -o {output_dir}\comparison.csv'
        print("Comparing registry hives...")
        subprocess.run(command, shell=True)
        print("Comparison completed. Output saved.")
    else:
        print("Please select exactly two hives.")

def apply_transaction_logs():
    output_dir = r"C:\Users\Hasan\Desktop\regipy\output"
    os.makedirs(output_dir, exist_ok=True)
    hive = filedialog.askopenfilename(title="Select Registry Hive to Apply Logs")
    if hive:
        command = f'rla -f "{hive}" --out "{output_dir}"'
        print("Applying transaction logs using rla.exe...")
        subprocess.run(command, shell=True)
        print("Completed. Recovered hive saved.")        
        

if __name__ == "__main__":
    while True:
        print("Select an option:")
        print("1. Acquire registry hives")
        print("2. Analyze registry hives")
        print("3. Compare two registry hives")
        print("4. Apply transaction logs")
        print("5. Parse hive header")
        
        choice = input("Enter your choice (1-5): ")

        if choice == '1':
            acquire_registry_hives()
            break
        elif choice == '2':
            analyze_registry_hive()
            break
        elif choice == '3':
            compare_registry_hives()
            break
        elif choice == '4':
            apply_transaction_logs()
            break
        elif choice == '5':
            parse_hive_header()
            break
        else:
            print("Invalid choice. Try again.")

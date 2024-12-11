import subprocess
import os
import json

# Define the commands to automate
# here you will need to change the path to the volatility3 script to the path of your volatility3 script
# and the path to the memory file to the path of your memory file
memory_file = "D:\\college\\GradProject\\106-RedLine\\MemoryDump.mem"
path_to_volatility3 = "D:\\Forensics tools\\volatility3\\vol.py"
commands = {
    "cmdline":[
        "python", path_to_volatility3,
        "-f", memory_file, "windows.cmdline.CmdLine"
    ],
    "pslist":[
        "python", path_to_volatility3,
        "-f", memory_file, "windows.pslist.PsList"
    ],
    "psscan":[ 
        "python", path_to_volatility3,
        "-f", memory_file, "windows.psscan.PsScan"
    ],
    "malfind":[
        "python", path_to_volatility3,
        "-f", memory_file, "windows.malfind.Malfind"
    ]
}

# Function to run a command and save its output
# here you will need to change the second argument to the path of your output file
def run_command(command_name, command, output_dir):
    output_file = os.path.join(output_dir, f"{command_name}.json")
    try:
        print(f"Running: {command_name}")

        result = subprocess.run(command, text=True, capture_output=True)
        output_lines = result.stdout.splitlines()
        print(output_lines)
        # Parse the output based on the command
        # volatility3 output is in tabular format header line is the third line
        headers = output_lines[2].split()

        data = []
        for line in output_lines[3:]:  # Skip the header line
            values = line.split()
            entry = dict(zip(headers, values))
            if entry!={}:
                data.append(entry)
                
        # da lw 3ayz t3ml save ll stderr w return code
        # output_data = {
        #     "command": command,
        #     "data": data,
        #     "stderr": result.stderr,
        #     "returncode": result.returncode
        # }

        with open(output_file, "w") as outfile:
            # json.dump(output_data, outfile, indent=4)
            json.dump(data, outfile, indent=4)
        print(f"Output saved to {output_file}")
    except Exception as e:
        print(f"An error occurred while running {command_name}: {e}")

# Main function to execute all commands
def main():
    # Create the output directory if it doesn't exist
    output_dir = os.path.join(os.getcwd(), "memory_analysis")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    
    print("Starting Volatility 3 Automation...")

    # Execute each command
    for name, cmd in commands.items():
        run_command(name, cmd, output_dir)

    print("All commands executed. Check the output files for analysis.")

# Run the main function
if __name__ == "__main__":
    main()


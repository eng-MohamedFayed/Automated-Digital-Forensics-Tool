import os
import json
import re
import logging
import subprocess

class VolatilityWrapper:
    """
    Encapsulates logic for running Volatility commands and parsing output.
    """
    def __init__(self, volatility_path, memory_image, output_dir):
        self.volatility_path = volatility_path
        self.memory_image = memory_image
        self.output_dir = output_dir

        # Commands dictionary can be overridden by the user or expanded
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
        """
        if len(output_lines) < 3:
            return []

        headers = output_lines[2].split()
        data = []

        # Example custom parser for 'malfind'
        if command_name == "malfind":
            current_entry = None
            for line in output_lines[4:]:
                parts = line.split()
                if parts and parts[0].isdigit() and (len(parts) == 10 or len(parts) == 11):
                    if current_entry:
                        data.append(current_entry)
                    fields = parts
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
                    if parts and all(c in "0123456789abcdefABCDEF .-" for c in parts[0]):
                        current_entry["Hexdump"].append(line.strip())
                    elif ":" in line and line.split(":", 1)[1].strip():
                        current_entry["Disasm"].append(line)

            if current_entry:
                data.append(current_entry)
            return data

        elif command_name == "netscan":
            for line in output_lines[4:]:
                values = line.split()
                if values and (len(values) >= 2) and (values[1] in ["UDPv4", "UDPv6"]):
                    # Insert "N/A" for missing 'State'
                    values.insert(6, "N/A")
                entry = dict(zip(headers, values))
                if entry:
                    data.append(entry)
            return data

        elif command_name == "pslist":
            custom_headers = ['PID', 'PPID', 'ImageFileName', 'Offset(V)', 'Threads', 'Handles',
                              'SessionId', 'Wow64', 'CreateTime', 'ExitTime', 'File output']
            data = []
            for line in output_lines[3:]:
                line = line.strip()
                if not line:
                    continue
                tokens = line.split()
                if len(tokens) < 2:
                    continue
                pid = tokens[0]
                ppid = tokens[1]
                tokens = tokens[2:]
                image_file_name_tokens = []
                offset_v = None
                for idx, token in enumerate(tokens):
                    if re.match(r'^0x[0-9a-fA-F]+$', token):
                        offset_v = token
                        remaining_tokens = tokens[idx+1:]
                        break
                    else:
                        image_file_name_tokens.append(token)
                if not offset_v:
                    logging.warning(f"Offset(V) not found in line: {line}")
                    continue

                image_file_name = ' '.join(image_file_name_tokens)
                if len(remaining_tokens) >= 7:
                    threads = remaining_tokens[0]
                    handles = remaining_tokens[1]
                    session_id = remaining_tokens[2]
                    wow64 = remaining_tokens[3]
                    create_time = ' '.join(remaining_tokens[4:7])
                    exit_time = remaining_tokens[7] if len(remaining_tokens) > 7 else ''
                    file_output = ' '.join(remaining_tokens[8:]) if len(remaining_tokens) > 8 else ''
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
                else:
                    logging.warning(f"Not enough tokens after offset in line: {line}")
            return data

        else:
            # Default parsing logic
            for line in output_lines[4:]:
                values = line.split()
                entry = dict(zip(headers, values))
                if entry:
                    data.append(entry)
            return data

    def run_volatility_command(self, command_name, command_list=None, output_dir=None):
        """
        Execute a Volatility command (subprocess) and store output as JSON.
        Returns (output_file, parsed_data).
        """
        if not command_list:
            if command_name in self.commands:
                command_list = self.commands[command_name]
            else:
                logging.error(f"No command found for {command_name}.")
                return None, None

        if output_dir is None:
            output_dir = self.output_dir

        output_file = os.path.join(output_dir, f"{command_name}.json")

        try:
            logging.info(f"Running Volatility command: {command_name}")
            result = subprocess.run(command_list, text=True, capture_output=True, shell=True)
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
        Uses Volatility to dump memory of a given PID. Returns list of dropped files.
        """
        logging.info(f"Dumping memory for PID {pid}")
        volatility_command = [
            "python", self.volatility_path,
            "-f", self.memory_image,
            "-o", dump_dir,
            "windows.dumpfiles.DumpFiles",
            "--pid", str(pid)
        ]
        self.run_volatility_command(f"dumpfiles_{pid}", volatility_command, dump_dir)

        dumped_paths = []
        if os.path.isdir(dump_dir):
            for file_name in os.listdir(dump_dir):
                if file_name.lower().endswith((".exe", ".dll", ".exe.img", ".dll.img")):
                    dumped_paths.append(os.path.join(dump_dir, file_name))
        if dumped_paths:
            logging.info(f"Dumped files for PID {pid}: {dumped_paths}")
        else:
            logging.warning(f"No dumped executable files found for PID {pid}")
        return dumped_paths
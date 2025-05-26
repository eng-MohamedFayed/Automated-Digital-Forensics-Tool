import os
import re
import json
import logging

def filter_netscan_output(netscan_json_path):
    """
    Filter Volatility netscan output to collate UniqueOwners and GroupedConnections.
    Collect unique IP addresses for scanning. Returns (combined_data, foreign_addrs).
    """
    try:
        logging.info(f"Filtering netscan output: {netscan_json_path}")
        with open(netscan_json_path, 'r') as f:
            netscan_data = json.load(f)

        # Collect unique (Owner, PID)
        unique_owners = {(e.get("Owner"), e.get("PID")) for e in netscan_data
                         if e.get("Owner") and e.get("PID")}
        unique_owners_data = [{"Owner": o, "PID": p, "Malicious_IP": []} for (o, p) in unique_owners]

        owner_connections = {}
        foreign_addrs = set()

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
            if ip and ip != "*":
                # Exclude local ranges: 0.0.0.0, 10.*, 192.168.*, 172.16->31, and "::"
                if not re.match(r"^(::|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1]))", ip):
                    foreign_addrs.add(ip)

        grouped_connections_data = [
            {"Owner": owner, "Connections": conns}
            for owner, conns in owner_connections.items()
        ]

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
    Loads the userassist JSON, filters out entries that do not meet specific criteria,
    and saves results to the given output path.
    """
    try:
        logging.info(f"Filtering userassist output: {userassist_json_path}")
        with open(userassist_json_path, 'r') as f:
            userassist_data = json.load(f)

        valid_entries = []
        for entry in userassist_data:
            hive = entry.get("Hive", "")
            offset = entry.get("Offset", "")
            # The original code checks if len(hive) > 2 or len(offset) > 2 or hive.startswith("\\\\")
            # or offset.startswith("\\\\") or offset.startswith("0x")
            if len(hive) > 2 or len(offset) > 2 or hive.startswith("\\\\") or offset.startswith("\\\\") or offset.startswith("0x"):
                valid_entries.append(entry)

        with open(output_path, 'w') as outfile:
            json.dump(valid_entries, outfile, indent=4)

        logging.info(f"Filtered userassist data saved to {output_path}")
        return valid_entries

    except Exception as e:
        logging.error(f"Error filtering userassist data: {e}")
        return None
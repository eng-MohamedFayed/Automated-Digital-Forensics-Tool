import os
import json
import logging
import hashlib
import requests
from time import sleep

class VirusTotalScanner:
    """
    Handles scanning of files and IP addresses via the VirusTotal API.
    Manages rotating between multiple API keys to handle rate limits.
    """
    def __init__(self, vt_api_keys):
        self.vt_api_keys = vt_api_keys
        self.vt_key_turn = 0
        self.vt_key_use_counter = 0
        self.vt_file_results = []
        self.vt_ip_results = {}

    def _get_current_api_key(self):
        return self.vt_api_keys[self.vt_key_turn]

    def _rotate_api_key(self):
        self.vt_key_use_counter += 1
        # Switch the key after 4 uses (you can adjust this as needed)
        if self.vt_key_use_counter % 4 == 0:
            self.vt_key_turn = (self.vt_key_turn + 1) % len(self.vt_api_keys)

    def scan_file_with_virustotal(self, file_path):
        """
        Upload a file to VirusTotal for scanning or retrieve analysis if it exists.
        Returns a dict with key investigative details or {"error": "Rate limit reached"}.
        """
        try:
            logging.info(f"Scanning file with VirusTotal: {file_path}")
            with open(file_path, 'rb') as file:
                data = file.read()

            file_data = {
                'filename': os.path.basename(file_path),
                'full_path': file_path,
                'file_size': os.path.getsize(file_path),
                'md5': hashlib.md5(data).hexdigest(),
                'sha256': hashlib.sha256(data).hexdigest(),
            }

            headers = {"x-apikey": self._get_current_api_key()}
            # First check if VirusTotal already has the file
            response = requests.get(
                f"https://www.virustotal.com/api/v3/files/{file_data['sha256']}",
                headers=headers
            )

            # If the file is found, retrieve the existing analysis
            if response.status_code == 200:
                result = response.json()
                attributes = result.get('data', {}).get('attributes', {})

                last_analysis_stats = attributes.get('last_analysis_stats', {})
                file_data['virustotal_detected'] = last_analysis_stats.get('malicious', 0)
                file_data['total_scans'] = sum(last_analysis_stats.values())
                file_data['malware_status'] = 'Malicious' if file_data['virustotal_detected'] > 0 else 'Clean'

                detections = []
                last_analysis_results = attributes.get('last_analysis_results', {})
                for engine_name, engine_data in last_analysis_results.items():
                    if engine_data.get('category') == 'malicious':
                        detections.append({
                            'engine_name': engine_name,
                            'result': engine_data.get('result')
                        })
                file_data['detections'] = detections

                file_data['tags'] = attributes.get('tags', [])
                file_data['reputation'] = attributes.get('reputation')

                # Sandbox verdicts
                sandbox_verdicts = attributes.get('sandbox_verdicts', {})
                sandbox_summaries = []
                for sandbox_name, verdict in sandbox_verdicts.items():
                    sandbox_summaries.append({
                        'sandbox_name': sandbox_name,
                        'category': verdict.get('category'),
                        'malware_classification': verdict.get('malware_classification'),
                    })
                file_data['sandbox_analysis'] = sandbox_summaries

                logging.info(f"VirusTotal scan (existing) completed for {file_path}: {file_data['malware_status']}")
                return file_data

            elif response.status_code == 429:
                logging.warning(f"Rate limit reached for current API key while scanning file {file_path}.")
                return {"error": f"Rate limit reached using API {self.vt_api_keys[self.vt_key_turn]}"}

            # If the file is not found in VirusTotal (404), upload it
            elif response.status_code == 404:
                logging.info(f"File {file_path} not found in VirusTotal. Uploading...")
                with open(file_path, 'rb') as file:
                    response = requests.post(
                        "https://www.virustotal.com/api/v3/files",
                        headers=headers,
                        files={"file": (file_data['filename'], file)}
                    )
                if response.status_code in (200, 201):
                    result = response.json()
                    analysis_id = result.get('data', {}).get('id')
                    if analysis_id:
                        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                        # Wait for the analysis to complete
                        while True:
                            analysis_response = requests.get(analysis_url, headers=headers)
                            analysis_result = analysis_response.json()
                            status = analysis_result.get('data', {}).get('attributes', {}).get('status')
                            if status == 'completed':
                                attributes = analysis_result.get('data', {}).get('attributes', {})
                                stats = attributes.get('stats', {})
                                file_data['malicious_detections'] = stats.get('malicious', 0)
                                file_data['total_scans'] = sum(stats.values())
                                file_data['malware_status'] = 'Malicious' if file_data['malicious_detections'] > 0 else 'Clean'

                                results = attributes.get('results', {})
                                detections = []
                                for engine_name, engine_data in results.items():
                                    if engine_data.get('category') == 'malicious':
                                        detections.append({
                                            'engine_name': engine_name,
                                            'result': engine_data.get('result')
                                        })
                                file_data['detections'] = detections
                                file_data['tags'] = attributes.get('tags', [])

                                logging.info(f"VirusTotal analysis completed for {file_path}: {file_data['malware_status']}")
                                return file_data
                            else:
                                logging.info("Waiting for VirusTotal analysis to complete...")
                                sleep(15)
                    else:
                        logging.error("No analysis ID returned from VirusTotal.")
                        return None
                else:
                    logging.error(f"Error uploading {file_path} using API {self.vt_api_keys[self.vt_key_turn]} to VirusTotal: {response.status_code} {response.text}")
                    return None

            else:
                logging.error(f"Error scanning {file_path} with VirusTotal using API {self.vt_api_keys[self.vt_key_turn]}: {response.status_code} {response.text}")
                return None

        except Exception as e:
            logging.error(f"Error checking {file_path} using API {self.vt_api_keys[self.vt_key_turn]} in VirusTotal: {e}")
            return None

    def scan_ip_with_virustotal(self, ip):
        """
        Check an IP address against VirusTotal's IP address database and return essential data.
        Returns a dict or {"error": "Rate limit reached"}.
        """
        try:
            logging.info(f"Scanning IP with VirusTotal: {ip}")
            headers = {"x-apikey": self._get_current_api_key()}
            response = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers=headers
            )
            if response.status_code == 200:
                result = response.json()
                attributes = result.get("data", {}).get("attributes", {})

                data = {
                    "ip_address": ip,
                    "country": attributes.get("country"),
                    "asn": attributes.get("asn"),
                    "as_owner": attributes.get("as_owner"),
                    "reputation": attributes.get("reputation"),
                    "tags": attributes.get("tags", []),
                    "last_modification_date": attributes.get("last_modification_date"),
                }

                last_analysis_stats = attributes.get("last_analysis_stats", {})
                malicious_count = last_analysis_stats.get("malicious", 0)
                suspicious_count = last_analysis_stats.get("suspicious", 0)
                data['malicious_count'] = malicious_count
                data['suspicious_count'] = suspicious_count
                data['total_scans'] = sum(last_analysis_stats.values())
                data["is_malicious"] = (malicious_count > 0 or suspicious_count > 0)

                # Extract "malicious"/"suspicious" detection details
                detections = []
                last_analysis_results = attributes.get('last_analysis_results', {})
                for engine_name, engine_data in last_analysis_results.items():
                    category = engine_data.get('category')
                    if category in ['malicious', 'suspicious']:
                        detections.append({
                            'engine_name': engine_name,
                            'category': category,
                            'result': engine_data.get('result')
                        })
                data['detections'] = detections

                logging.info(f"VirusTotal scan completed for IP {ip}: "
                             f"{'Malicious' if data['is_malicious'] else 'Clean'}")
                return data

            elif response.status_code == 429:
                logging.warning(f"Rate limit reached for current API key while scanning IP {ip}.")
                return {"error": f"Rate limit reached for current API key: {self.vt_api_keys[self.vt_key_turn]}"}

            else:
                logging.error(f"Error scanning IP {ip} using API {self.vt_api_keys[self.vt_key_turn]} with VirusTotal: {response.status_code} {response.text}")
                return None

        except Exception as e:
            logging.error(f"Error scanning IP {ip} using API {self.vt_api_keys[self.vt_key_turn]} in VirusTotal: {e}")
            return None

    def rotate_key_after_request(self):
        """
        Called after each file or IP scan to increment usage and possibly rotate the key.
        """
        self._rotate_api_key()
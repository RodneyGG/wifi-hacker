import os
import subprocess
import csv
import time
import signal
from wifi_base import WifiBase

class WifiScanner(WifiBase):
    def scan_networks(self, scan_duration=10):
        self.log_message(f"Scanning for WPA/WPA2 networks for {scan_duration} seconds...")
        
        #delete previous scan to start fresh
        delete_files = ["scan-01.csv", "scan-01.kismet.csv", "scan-01.log.csv"]
        
        for pattern in delete_files:
            try:
                if os.path.exists(pattern):
                    os.unlink(pattern)
            except Exception as error:
                self.log_message(f"Failed to remove {pattern}: {str(error)}", 'warning')
        
        #start scanning for networks
        scan_cmd = f"airodump-ng {self.interface} --write scan --output-format csv"
        
        scan_process = subprocess.Popen(
                    scan_cmd,
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    preexec_fn=os.setsid
                    )
    
        if not scan_process.pid:
            self.log_message("Failed to start scan process", 'error')
            return None
        #wait for the scan duration to complete
        time.sleep(scan_duration)
        
        #terminate process
        os.killpg(os.getpgid(scan_process.pid), signal.SIGTERM)
        
        return self.analyze_scan_results()
        
    def analyze_scan_results(self):
        #identify which is the strongest network
        try:
            with open("scan-01.csv", newline='') as csv_file:
                csv_reader = csv.reader(csv_file)
                best_network = None
                strongest_signal = -999 
                
                for row in csv_reader:
                    if self.is_valid_wpa_network(row):
                        try:
                            signal_strength = int(row[8].strip())
                            if signal_strength > strongest_signal:
                                strongest_signal = signal_strength
                                best_network = {
                                    'bssid': row[0].strip(),
                                    'channel': row[3].strip(),
                                    'ssid': row[13].strip(),
                                    'power': signal_strength
                                }
                        except (ValueError, IndexError):
                            continue
                
                if best_network:
                    self.log_message(f"Found target network: {best_network['ssid']}")
                else:
                    self.log_message("No suitable WPA/WPA2 networks found", 'warning')
                    
                return best_network
        except FileNotFoundError:
            self.log_message("Scan results file not found", 'error')
            return None
        except Exception as error:
            self.log_message(f"Error parsing scan results: {str(error)}", 'error')
            return None
        
    def is_valid_wpa_network(self, row):
        #check if valid netword
        return (
            len(row) >= 14 and 
            row[0].strip() != 'BSSID' and 
            "WPA" in row[5]
        )
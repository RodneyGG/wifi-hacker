import os
import subprocess
from datetime import datetime
from wifi_base import WifiBase

class WPACracker(WifiBase):
    def __init__(self, interface='wlan0', debug=False, wordlist_path=None):
        super().__init__(interface, debug)
        self.wordlist = wordlist_path or self._find_default_wordlist()
        if not self.wordlist:
            raise FileNotFoundError("No suitable wordlist found for cracking.")
        self.results_file = None 
        
    def _find_default_wordlist(self):
        """Locate a suitable default wordlist if none specified."""
        common_paths = [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/wordlists/rockyou.txt.gz",
            "/usr/share/dict/wordlist-probable.txt",
            "/opt/wordlists/rockyou.txt"
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                self.log_message(f"Found default wordlist: {path}")
                return path
                
        self.log_message("No suitable wordlist found", "error")
        return None
    
    def convert_capture_to_hashcat(self, pcap_file):
        if not pcap_file or not os.path.exists(pcap_file):
            self.log_message("Invalid Pcap File", "error")   
            return None
        
        self.log_message("Converting capture to .hc22000 using hcxpcapngtool...")
        
        output_file = f"{os.path.splitext(pcap_file)[0]}.hc22000"
        cmd = ["hcxpcapngtool", "-o", output_file, pcap_file]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if result.returncode != 0:
            self.log_message(f"hcxpcapngtool failed: {result.stderr.decode().strip()}", "error")
            return None
        
        if os.path.exists(output_file):
            self.log_message(f"Conversion successful: {output_file}")
            return output_file
        
        self.log_message("Conversion to .hc22000 failed", "error")
        return None
    
    def crack_hash(self, hash_file):
        if not hash_file or not os.path.exists(hash_file):
            self.log_message("Invalid hash file", 'error')
            return False
            
        if not self.wordlist or not os.path.exists(self.wordlist):
            self.log_message("Invalid wordlist", 'error')
            return False
        
        #show time stamp for each crack 
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results_file = f"cracked_results_{timestamp}.txt"
        
        self.log_message(f"Starting Hashcat attack with wordlist: {self.wordlist}")
        
        hashcat_command = [
            "hashcat",
            "-m", "22000",
            hash_file,
            self.wordlist,
            "--force",
            "-o", self.results_file,
            "--potfile-disable"
        ]
        
        try:
            subprocess.run(hashcat_command, check=True)
            if os.path.exists(self.results_file) and os.path.getsize(self.results_file) > 0:
                self.log_message(f"Hashcat finished. Results saved to {self.results_file}")
                return True
            else:
                self.log_message("Hashcat completed but results file is empty", "error")
                return False
        except subprocess.CalledProcessError as e:
            self.log_message(f"Hashcat failed: {e}", "error")
            return False
        
    def extract_password(self):
        if not self.results_file or not os.path.exists(self.results_file):
            self.log_message("Results file not found", "error")
            return None

        try:
            with open(self.results_file, "r") as file:
                for line in file:
                    line = line.strip()
                    if ':' in line:
                        # Split on first colon only
                        parts = line.split(':', 1)
                        if len(parts) == 2 and parts[1]:
                            return parts[1].strip()
        except Exception as error:
            self.log_message(f"Error reading results file: {str(error)}", "error")

        self.log_message("No password found in results file", "error")
        return None

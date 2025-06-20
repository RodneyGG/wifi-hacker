#!/usr/bin/env python3
from wifi_hacker import WifiHacker
import argparse
import sys
import os

class WifiCrackerApp:
    def __init__(self):
        self.interface = "wlan0"
        self.wordlist = None
        self.debug = False
        self.ssid = None
        self.bssid = None
        
    def parse_arguments(self):
        parser = argparse.ArgumentParser(
            description="WPA/WPA2 Network Cracker - For Educational and Authorized Testing Only ;)",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        parser.add_argument('-i', '--interface', 
                        default='wlan0',
                        help='Wireless interface to use')
        parser.add_argument('-w', '--wordlist',
                        help='Path to wordlist file')
        parser.add_argument('-d', '--debug',
                        action='store_true',
                        help='Enable verbose debug output')
        parser.add_argument('--ssid',              
                            help='Target network SSID')
        parser.add_argument('--bssid',             
                            help='Target network BSSID')
        
        args = parser.parse_args()
        
        #valitadate if intereface exist
        if not os.path.exists(f'/sys/class/net/{args.interface}'):
            sys.stderr.write(f"Error: Interface {args.interface} not found\n")
            sys.exit(1)
            
        #verify wordlist
        if args.wordlist and not os.path.isfile(args.wordlist):
            sys.stderr.write(f"Error: Wordlist file not found: {args.wordlist}\n")
            sys.exit(1)
            
        self.interface = args.interface
        self.wordlist = args.wordlist
        self.debug = args.debug
        self.ssid = args.ssid       
        self.bssid = args.bssid     
        
    def display_warning(self):
        """Show legal disclaimer"""
        print("""
        WARNING: This tool is for educational purposes and authorized penetration testing only.
        Unauthorized use may violate laws and regulations. Use only on networks you own or have permission to test.
        WALANG KASALANAN SI LLOYD AREVALO PAG MAY GINAWA KANG MASAMA
        """)
    
    def run(self):
        try:
            self.parse_arguments()
            self.display_warning()
            
            # Create and execute the WifiHacker
            hacker = WifiHacker(
                interface=self.interface,
                wordlist=self.wordlist,
                debug=self.debug,
                ssid=self.ssid,      
                bssid=self.bssid     
            )
            hacker.execute()
            
        except KeyboardInterrupt:
            print("\n[!] Operation cancelled by user")
            sys.exit(0)
        except Exception as error:
            sys.stderr.write(f"\n[!] Fatal error: {str(error)}\n")
            if self.debug:
                import traceback
                traceback.print_exc()
            sys.exit(1)

if __name__ == "__main__":
    app = WifiCrackerApp()
    app.run()
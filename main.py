#!/usr/bin/env python3
import os
import sys
import argparse
import traceback
from wifi_hacker import WifiHacker

class App:
    warning_msg = """
                WARNING: This tool is for educational purposes and authorized penetration testing only.
                Unauthorized use may violate laws and regulations. Use only on networks you own or have permission to test.
                WALANG KASALANAN SI LLOYD AREVALO PAG MAY GINAWA KANG MASAMA
                """
    
    def __init__(self):
        self.args = None
        self.parser = self._create_argument_parser()
        
    def _create_argument_parser(self):
        parser = argparse.ArgumentParser(
            description="WPA/WPA2 Network Cracker - For Educational and Authorized Testing Only",
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
        return parser
        
    def _validate_arguments(self):
        if not os.path.exists(f'/sys/class/net/{self.args.interface}'):
            raise FileNotFoundError(f"Interface {self.args.interface} not found")
            
        if self.args.wordlist and not os.path.isfile(self.args.wordlist):
            raise FileNotFoundError(f"Wordlist file not found: {self.args.wordlist}")
    
    def _display_warning(self):
        print(self.warning_msg)
        
    def _handle_error(self, error):
        sys.stderr.write(f"\n[!] Fatal error: {str(error)}\n")
        if self.args.debug:
            traceback.print_exc()
        sys.exit(1)
        
    def _handle_keyboard_interrupt(self):
        print("\n[!] Operation cancelled by user")
        sys.exit(0)
        
    def run(self):
        try:
            self.args = self.parser.parse_args()
            self._validate_arguments()
            self._display_warning()
            
            hacker = WifiHacker(
                interface=self.args.interface,
                wordlist=self.args.wordlist,
                debug=self.args.debug
            )
            hacker.execute()
            
        except KeyboardInterrupt:
            self._handle_keyboard_interrupt()
        except Exception as e:
            self._handle_error(e)

if __name__ == "__main__":
    app = App()
    app.run()
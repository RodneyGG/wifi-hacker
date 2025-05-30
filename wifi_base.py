import os 
import logging
import subprocess
from datetime import datetime

class WifiBase:
    def __init__(self, interface="wlan0", debug=False):
        self.interface = interface
        self.monitor_mode_iface = interface + "mon"
        self.debug = debug
        self.setup_logging()
        
    def setup_logging(self):
        #set the logging level depend on the debug flag
        if self.debug:
            log_level = logging.DEBUG #10
        else:
            log_level = logging.INFO #20
            
        #log msg format
        log_format = "%(asctime)s - %(levelname)s - %(message)s"
        
        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=[
                logging.FileHandler('wifi_cracker.log'),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger("WifiCracker")
    
    def run_cmd(self, cmd, timeout=30):
        #Open cmd
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                check=True,
                timeout=timeout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if self.debug:
                self.logger.debug(f"Command: {cmd}\nOutput: {result.stdout}")

            return result.stdout

        except subprocess.TimeoutExpired:
            self.logger.warning(f"Command timed out: {cmd}")
            return ""

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command failed: {cmd}\nError: {e.stderr}")
            return ""
    
    def log_message(self, message, level="info"):
        getattr(self.logger, level)(message)
        
from modules.wifi_base import WifiBase

class WifiInterface(WifiBase):
    def __init__(self, interface="wlan0", debug=False):
        super().__init__(interface, debug)
        self.original_mode = self.wifi_mode()
        
    def wifi_mode(self):
        command = f"iwconfig {self.interface} | grep Mode"
        result = self.run_cmd(command)
        
        #check if the wifi is already on monitor mode
        if result == "Mode:Monitor":
            return "monitor"
        else:
            return "managed"
    
    def enable_monitor_mode(self):
        self.log_message("Enabling Monitor Mode...") #WAG MONG SUSUBUKAN SA SM PLS
        try:
            self.run_cmd(f"ifconfig {self.interface} down")
            self.run_cmd(f"iwconfig {self.interface} mode monitor")
            self.run_cmd(f"ifconfig {self.interface} up")
            self.log_message(f"{self.interface} is now in monitor mode.")
        except Exception as error:
            self.log_message(f"Failed to enable monitor mode due to {error}")
        
    def disable_monitor_mode(self):
        self.log_message("Disabling Monitor Mode...") #WAG MONG SUSUBUKAN SA SM PLS
        try:
            self.run_cmd(f"ifconfig {self.interface} down")
            self.run_cmd(f"iwconfig {self.interface} mode managed")
            self.run_cmd(f"ifconfig {self.interface} up")
            self.log_message(f"{self.interface} is now in managed mode.")
        except Exception as error:
            self.log_message(f"Failed to disable monitor mode due to {error}")
    
    def reset_mode(self):
        if self.original_mode == "monitor":
            return self.enable_monitor_mode()
        return self.disable_monitor_mode()
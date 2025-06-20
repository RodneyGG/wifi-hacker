<a href="https://www.buymeacoffee.com/RodneyGG" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50" width="210">
</a>


# Wifi Hacker

**Educational WPA/WPA2 Network Cracker (For Authorized Testing Only)**

> ⚠️ **DISCLAIMER:**  
> This tool is intended for **educational purposes and authorized penetration testing only**.  
> **DO NOT** use this tool on networks that you do not own or do not have explicit permission to test.  
> Unauthorized use may be illegal and may result in prosecution.  
> **The author is not responsible for any misuse or damage caused by this tool.**

---

## Overview

Wifi Hacker is a Python-based tool designed to automate the process of scanning for Wi-Fi networks, capturing WPA/WPA2 handshakes, and attempting to crack the Wi-Fi password using a wordlist. It is intended for educational and authorized security testing only.

This tool abuses leaked password lists like `rockyou.txt` to try and decrypt the captured handshake. If the Wi-Fi password is weak or commonly used, it might get cracked fast. This is a good way to learn about network security.

---

## Requirements

- **Operating System:** Linux (tested on Kali Linux)
- **Python:** 3.6+
- **Root Privileges:** Required
- **Wireless Card:** Must support monitor mode
- **Dependencies/Tools:**  
  Install all required tools with:
  ```bash
  sudo apt update
  sudo apt install aircrack-ng hashcat hcxtools wireless-tools -y
  ```
  - `aircrack-ng` (provides `airodump-ng`)
  - `hcxpcapngtool` (provided by `hcxtools`)
  - `hashcat`
  - `iwconfig` (provided by `wireless-tools`)
- **Python Modules:**  
  The following modules must be present in the `modules/` directory:
  - `credential_logger.py`
  - `handshake_capturer.py`
  - `wpa_cracker.py`
  - `wifi_interface.py`
  - `wifi_scanner.py`

---

## New Command-Line Options and Tools

### New Options

- `--ssid` — Target network SSID (skip scan prompt)
- `--bssid` — Target network BSSID (skip scan prompt)

You can now directly specify the SSID and/or BSSID of the network you want to attack, bypassing the interactive scan selection.

### Additional Tools Used

These tools/utilities are now part of the workflow or supported for added flexibility:

- **hcxpcapngtool** — Used to convert captured handshakes for compatibility with hashcat.
- **hashcat** — Used for high-performance password cracking.
- **airodump-ng** — For capturing WPA/WPA2 handshakes.
- **iwconfig** — For wireless interface management and information.

---

## Installation

1. **Clone the repository:**
    ```bash
    git clone https://github.com/RodneyGG/wifi_hacker.git
    cd wifi_hacker
    ```

2. **Install required system tools:**  
   You can install all the necessary tools with:
    ```bash
    sudo apt update
    sudo apt install aircrack-ng hashcat hcxtools wireless-tools -y
    ```
   - `aircrack-ng` provides `airodump-ng`
   - `hcxtools` provides `hcxpcapngtool`
   - `hashcat` is for password cracking
   - `wireless-tools` provides `iwconfig`

3. **Ensure you have a wordlist:**  
   By default, the tool tries to use `rockyou.txt` or other common wordlists.  
   If not present, download and extract `rockyou.txt`:
    ```bash
    sudo apt install wordlists
    gzip -d /usr/share/wordlists/rockyou.txt.gz
    ```

4. **Prepare your wireless interface:**  
   Make sure your Wi-Fi adapter supports monitor mode and is recognized (e.g., `wlan0`).

---

## How to Use

1. **Run the tool with root privileges**  
   You can run the program using:
   ```bash
   sudo python3 main.py
   ```
   or, if you are using the original main file:
   ```bash
   sudo python3 wifi_hacker.py [options]
   ```

2. **Options you can use:**

   | Option                 | Description                                    |
   |------------------------|------------------------------------------------|
   | `-i`, `--interface`    | Wireless interface to use (default: wlan0)     |
   | `-w`, `--wordlist`     | Path to wordlist file (default: auto-detect)   |
   | `-d`, `--debug`        | Enable verbose debug output                    |
   | `--ssid`               | Target network SSID (skip scan prompt)         |
   | `--bssid`              | Target network BSSID (skip scan prompt)        |

3. **Examples:**

   - Use default interface and wordlist:
     ```bash
     sudo python3 main.py
     ```
   - Specify a different interface:
     ```bash
     sudo python3 main.py -i wlan1
     ```
   - Use a custom wordlist:
     ```bash
     sudo python3 main.py -w /path/to/your/wordlist.txt
     ```
   - Enable debug output:
     ```bash
     sudo python3 main.py -d
     ```
   - **Specify SSID and/or BSSID directly (bypass scan):**
     ```bash
     sudo python3 main.py --ssid MyNetwork --bssid 00:11:22:33:44:55
     ```
   - Combine options:
     ```bash
     sudo python3 main.py -i wlan1 -w /usr/share/wordlists/rockyou.txt --ssid MyNetwork --bssid 00:11:22:33:44:55 -d
     ```

   > **Note:** If you do not specify a wordlist, the script will search for common wordlist files automatically.
   > Always run as **root**.

---

## How It Works

1. **Puts your Wi-Fi interface into monitor mode**
2. **Scans for available WPA/WPA2 networks**
3. **Prompts you to select a target network** (unless you use `--ssid`/`--bssid`)
4. **Captures the WPA handshake from the target**
5. **Attempts to crack the handshake using the wordlist**
6. **Logs credentials if successful and cleans up temporary files**

---

## Important Notes

- **Only use on networks you own or have explicit permission to test!**
- Interfering with networks you do not own is illegal and unethical.
- The script automatically cleans up and resets your interface after running.

---

## Troubleshooting

- If you receive "Missing required tools" errors, ensure all dependencies are installed and in your `$PATH`.
- If your interface is not found, check its name with `iwconfig` or `ip link`.
- For wordlist errors, ensure the path is correct and file is readable.

---

This program was created by **Lloyd Rodney Arevalo** strictly for educational purposes only.

The creator does not condone or support any form of illegal activity, including unauthorized access to Wi-Fi networks or systems.

✅ Always obtain proper permission before attempting any form of testing or hacking.  
✅ You are solely responsible for how you use this tool.

Use this tool only on your own networks or with explicit consent from the network owner.

**Use responsibly!**

---
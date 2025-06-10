# Wifi Hacker

**Educational WPA/WPA2 Network Cracker (For Authorized Testing Only)**

> ⚠️ **DISCLAIMER:**  
> This tool is intended for **educational purposes and authorized penetration testing only**.  
> **DO NOT** use this tool on networks that you do not own or do not have explicit permission to test.  
> Unauthorized use may be illegal and may result in prosecution.  
> **The author is not responsible for any misuse or damage caused by this tool.**

---

## Overview

 Wifi Hacker is a Python-based tool designed to automate the process of scanning for Wi-Fi networks, capturing WPA/WPA2 handshakes, and attempting to crack the Wi-Fi password using a wordlist. It leverages popular tools like `airodump-ng`, `hcxpcapngtool`, and `hashcat` under the hood.

 This tool abuses leaked password lists like `rockyou.txt` to try and decrypt the captured handshake. If the Wi-Fi password is weak or commonly used, it might get cracked fast. This is a good way to learn how important strong passwords really are.

---

## Requirements

- **Operating System:** Linux (tested on Kali Linux)
- **Python:** 3.6+
- **Root Privileges:** Required
- **Wireless Card:** Must support monitor mode
- **Dependencies/Tools:**
  - `airodump-ng`
  - `hcxpcapngtool`
  - `hashcat`
  - `iwconfig`
- **Python Modules:**  
  The following modules must be present in the `modules/` directory:
  - `credential_logger.py`
  - `handshake_capturer.py`
  - `wpa_cracker.py`
  - `wifi_interface.py`
  - `wifi_scanner.py`

---

## Installation

1. **Clone the repository:**
    ```bash
    git clone https://github.com/RodneyGG/wifi_hacker.git
    cd wifi_hacker
    ```

2. **Install required system tools:**
    ```bash
    sudo apt update
    sudo apt install aircrack-ng hashcat hcxtools -y
    ```

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

## How to Run

You can run the program using:

```bash
sudo python3 main.py
```

or, if you are using the original main file:

```bash
sudo python3 wifi_hacker.py [options]
```

---

## Options

| Option | Description |
|--------|-------------|
| `-i`, `--interface` | Wireless interface to use (default: wlan0) |
| `-w`, `--wordlist`  | Path to wordlist file (default: auto-detect from common locations) |
| `-d`, `--debug`     | Enable verbose debug output |

### Sample Usage

#### 1. Using the default interface and auto-detected wordlist:
```bash
sudo python3 main.py
```

#### 2. Specifying a wireless interface:
```bash
sudo python3 main.py -i wlan1
```

#### 3. Specifying a custom wordlist:
```bash
sudo python3 main.py -w /path/to/your/wordlist.txt
```

#### 4. Enabling debug output:
```bash
sudo python3 main.py -d
```

#### 5. Combining options:
```bash
sudo python3 main.py -i wlan1 -w /usr/share/wordlists/rockyou.txt -d
```

- If you do not specify a wordlist, the script will search for common wordlist files automatically.
- Always run as **root**.

---

## How It Works

1. **Puts your Wi-Fi interface into monitor mode**
2. **Scans for available WPA/WPA2 networks**
3. **Prompts you to select a target network**
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
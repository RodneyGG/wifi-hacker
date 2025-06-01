import os
from datetime import datetime

class CredentialLogger:
    @staticmethod
    def save_credentials(ssid, bssid, password, output_dir='craked_wifi'):
        
        filename = os.path.join(output_dir, "cracked_credentials.txt")
        with open(filename, "a") as file:
            time_stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            line = "-" * 30
            file.write(
                f"{time_stamp} | ssid : {ssid} |\n"
                f"BSSID : {bssid}\n"
                f"Password: {password}\n"
                f"{line}\n\n"
            )
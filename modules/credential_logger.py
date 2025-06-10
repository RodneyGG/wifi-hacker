from datetime import datetime

class CredentialLogger:
    @staticmethod
    def save_credentials(ssid, bssid, password, filename="cracked_credential.txt"):
        with open(filename, "a") as file:
            time_stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            line = "-" * 30
            file.write(
                f"{time_stamp} | ssid : {ssid} |"
                f"BSSID : {bssid}"
                f"Password: {password}"
                f"{line}"
            )
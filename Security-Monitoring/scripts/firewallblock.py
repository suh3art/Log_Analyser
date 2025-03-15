import os
import platform
import time
import pandas as pd

# File path to malicious logs
malicious_logs_file = "../logs/malicious_logs.csv"

def get_operating_system():
    """Detects the user's OS."""
    system = platform.system().lower()
    if "windows" in system:
        return "windows"
    elif "linux" in system:
        return "linux"
    elif "darwin" in system:
        return "mac"
    else:
        print("❌ Unsupported OS detected.")
        exit(1)

def load_malicious_ips():
    """Load all malicious IPs from malicious_logs.csv"""
    try:
        df = pd.read_csv(malicious_logs_file)
        if "ip" in df.columns:
            return df["ip"].unique().tolist()
        else:
            print("⚠️ No IP column found in malicious logs.")
            return []
    except FileNotFoundError:
        print("❌ Error: malicious_logs.csv not found.")
        return []

def block_ips(ips, os_type):
    """Block all IPs based on the user's OS."""
    if not ips:
        print("⚠️ No malicious IPs to block.")
        return

    print(f"🚨 Blocking {len(ips)} IPs on {os_type} system...")

    if os_type == "windows":
        for ip in ips:
            os.system(f"netsh advfirewall firewall add rule name='Blocked_{ip}' dir=in action=block remoteip={ip}")
    elif os_type == "linux":
        for ip in ips:
            os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
    elif os_type == "mac":
        for ip in ips:
            os.system(f"sudo pfctl -t blocked_ips -T add {ip}")

    print("✅ All IPs blocked successfully.")

def unblock_ips(ips, os_type):
    """Unblock all blocked IPs after 120 seconds."""
    if not ips:
        return

    print(f"⏳ Scheduled to unblock {len(ips)} IPs after 120 seconds...")

    time.sleep(120)  # Unblock after 10 seconds

    if os_type == "windows":
        for ip in ips:
            os.system(f"netsh advfirewall firewall delete rule name='Blocked_{ip}'")
    elif os_type == "linux":
        for ip in ips:
            os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
    elif os_type == "mac":
        os.system(f"sudo pfctl -T flush -t blocked_ips")  # ✅ FIXED COMMAND

    print("✅ All IPs unblocked successfully.")

def show_blocked_ips(os_type):
    """Displays all currently blocked IPs."""
    print("\n📌 Showing currently blocked IPs:")

    if os_type == "windows":
        os.system("netsh advfirewall firewall show rule name=all | findstr Block")
    elif os_type == "linux":
        os.system("sudo iptables -L INPUT -v -n | grep DROP")
    elif os_type == "mac":
        os.system("sudo pfctl -T show -t blocked_ips")

def main():
    os_type = get_operating_system()
    malicious_ips = load_malicious_ips()

    if not malicious_ips:
        print("⚠️ No malicious IPs found. Exiting...")
        return

    # ✅ Block all IPs
    block_ips(malicious_ips, os_type)

    # ✅ Show currently blocked IPs
    show_blocked_ips(os_type)

    # ✅ Unblock all IPs after 120 seconds
    os.system("nohup bash -c 'sleep 120 && sudo pfctl -T flush -t blocked_ips' &")

if __name__ == "__main__":
    main()

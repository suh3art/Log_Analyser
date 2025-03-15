import os
import re
import pandas as pd
import time
import datetime
from collections import Counter
from asciichartpy import plot
from termcolor import colored

# Log file paths
log_files = {
    "access": "../logs/simulated_access.log",
    "auth": "../logs/simulated_auth.log",
    "attack": "../logs/simulated_attack.log"
}

# Regular expression to extract log details
log_pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>.*?)\] "(?P<request>[A-Z]+ [^ ]+) HTTP/1.1" (?P<status>\d+)')

def parse_logs(log_file):
    """Parses log files and returns structured data."""
    data = []
    if os.path.exists(log_file):
        with open(log_file, "r") as file:
            for line in file:
                match = log_pattern.search(line)
                if match:
                    data.append(match.groupdict())
    return pd.DataFrame(data)

def display_report():
    # Load and parse logs
    access_logs = parse_logs(log_files["access"])
    auth_logs = parse_logs(log_files["auth"])
    attack_logs = parse_logs(log_files["attack"])

    # Analysis: Calculate summary statistics
    total_requests = len(access_logs) + len(auth_logs) + len(attack_logs)
    attack_attempts = len(attack_logs)
    legitimate_traffic = len(access_logs)
    authentication_requests = len(auth_logs)

    # Extract top attack types
    attack_types = attack_logs["request"].value_counts().head(5).to_dict() if not attack_logs.empty else {}

    # Extract top attacking IPs
    attacking_ips = attack_logs["ip"].value_counts().head(5).to_dict() if not attack_logs.empty else {}

    # Extract attack statuses (200 or 403)
    attack_statuses = attack_logs["status"].value_counts().to_dict()

    # Attack types and frequency analysis
    attack_frequency = {}
    for attack in attack_logs["request"]:
        attack_type = attack.split(" ")[1]  # Extract the attack type from the request (e.g., "SQL_INJECTION")
        attack_frequency[attack_type] = attack_frequency.get(attack_type, 0) + 1

    # Recommendations
    recommendations = [
        "Implement IP rate limiting to prevent brute-force attacks.",
        "Use a Web Application Firewall (WAF) to block SQL Injection and XSS attacks.",
        "Monitor suspicious IPs and block repeated offenders.",
        "Strengthen authentication mechanisms (2FA, CAPTCHA).",
        "Perform regular penetration testing and security audits."
    ]
    
    # Display Report in Terminal with Colors
    print(colored("\n# Security Monitoring Report\n", "cyan", attrs=["bold"]))
    print(colored("## Summary", "yellow", attrs=["bold"]))
    print(f"- Total Requests: {colored(total_requests, 'green')}")
    print(f"- Attack Attempts: {colored(attack_attempts, 'red')}")
    print(f"- Legitimate Traffic: {colored(legitimate_traffic, 'green')}")
    print(f"- Authentication Requests: {colored(authentication_requests, 'blue')}")

    # **Detailed Analysis Section**
    print(colored("\n## Attack Analysis", "red", attrs=["bold"]))
    print(f"- Top Attack Vectors: {colored(str(attack_types), 'red')}")
    print(f"- Attack Status Breakdown (200/403): {colored(str(attack_statuses), 'red')}")
    print(f"- Top Attacking IPs: {colored(str(attacking_ips), 'red')}")
    print(f"- Attack Frequency (by Type): {colored(str(attack_frequency), 'magenta')}")

    # **Attack Status Insight**
    total_successful = attack_statuses.get("200", 0)
    total_failed = attack_statuses.get("403", 0)
    
    # Calculate success and failure rates as percentages (handle division by zero gracefully)
    success_rate = (total_successful / attack_attempts) * 100 if attack_attempts > 0 else 0
    failure_rate = (total_failed / attack_attempts) * 100 if attack_attempts > 0 else 0

    print(colored("\n### Attack Status Insights", "magenta", attrs=["bold"]))
    print(f"Successful Attacks (HTTP 200): {colored(total_successful, 'green')}")
    print(f"Failed Attacks (HTTP 403): {colored(total_failed, 'red')}")
    print(f"Success Rate: {colored(f'{success_rate:.2f}%', 'green')}")
    print(f"Failure Rate: {colored(f'{failure_rate:.2f}%', 'red')}")

    # **Attacking IP Insights**
    print(colored("\n### Top Attacking IPs (Frequency)", "magenta", attrs=["bold"]))
    for ip, count in attacking_ips.items():
        print(f"IP {colored(ip, 'red')} made {colored(count, 'yellow')} attack attempts.")

    # **Graphical Insights**
    print(colored("\n### Attack Frequency by Type (Line Chart)", "blue", attrs=["bold"]))
    attack_counts = list(attack_frequency.values())
    print(plot(attack_counts, {'height': 8, 'labels': list(attack_frequency.keys())}))

    # **Graphical Chart for Attack vs Legitimate Traffic**
    pie_data = [legitimate_traffic, attack_attempts]
    pie_labels = ["Legit Traffic", "Attacks"]
    print(colored("\n### Attack vs Legitimate Traffic (ASCII Chart)", "magenta", attrs=["bold"]))
    print(plot(pie_data, {'height': 5, 'labels': pie_labels}))

    # **Highest and Lowest Attack Insights**
    highest_attack = max(attack_frequency, key=attack_frequency.get)
    lowest_attack = min(attack_frequency, key=attack_frequency.get)
    highest_count = attack_frequency[highest_attack]
    lowest_count = attack_frequency[lowest_attack]

    print(colored("\n### Highest and Lowest Attack Insights", "yellow", attrs=["bold"]))
    print(f"Highest Attack Type: {colored(highest_attack, 'green')} with {colored(highest_count, 'green')} occurrences.")
    print(f"Lowest Attack Type: {colored(lowest_attack, 'red')} with {colored(lowest_count, 'red')} occurrences.")

    # **Recommendations Section**
    print(colored("\n## Recommendations", "yellow", attrs=["bold"]))
    for rec in recommendations:
        print(f"- {colored(rec, 'cyan')}")

    # **Additional Insights**
    print(colored("\n## Additional Insights and Actions", "cyan", attrs=["bold"]))
    print("- Conduct periodic security audits to identify new vulnerabilities.")
    print("- Update software regularly to patch known security flaws.")
    print("- Educate users on the importance of strong password policies.")
    print("- Leverage threat intelligence feeds to stay up-to-date on emerging threats.")
    
    time.sleep(1)  # Refresh every second (this keeps the screen updated, but avoids duplication)

if __name__ == "__main__":
    display_report()

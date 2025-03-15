import pandas as pd
import re
import os
from tabulate import tabulate

# Log file paths
access_log_file = "../logs/simulated_access.log"
auth_log_file = "../logs/simulated_auth.log"
structured_logs_file = "../logs/structured_logs.csv"
malicious_logs_file = "../logs/malicious_logs.csv"

# Define attack patterns
attack_patterns = {
    "BRUTE_FORCE": r'POST /login HTTP/1.1" 401',
    "SQL_INJECTION": r'GET /search\?q=.*(\' OR " OR `)',
    "XSS_ATTACK": r'GET /profile\?name=.*<script>.*</script>',
    "ADMIN_ACCESS": r'GET /admin HTTP/1.1" 403',
    "PATH_TRAVERSAL": r'GET /(etc|var|proc)/passwd',
    "REMOTE_FILE_INCLUSION": r'GET /index.php\?page=http://',
    "COMMAND_INJECTION": r'GET /ping\?ip=.*(;|&&|&|`)',
    "LFI_ATTACK": r'GET /index.php\?page=\.\./\.\./\.\./',
    "USER_ENUMERATION": r'POST /wp-json/wp/v2/users',
    "CSRF_ATTACK": r'POST /change-email\?email=.*',
    "RCE_ATTACK": r'GET /execute\?cmd=.*',
    "XXE_ATTACK": r'POST /upload-xml',
    "API_ABUSE": r'GET /api/user\?username=admin',
}

def parse_log(log_file):
    """Parses a log file and extracts structured data."""
    pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d+) (?P<size>\d+)'
    data = []

    try:
        with open(log_file, "r") as file:
            for line in file:
                match = re.match(pattern, line)
                if match:
                    data.append(match.groupdict())

        df = pd.DataFrame(data)
        if not df.empty:
            df["status"] = df["status"].astype(int)
            df["size"] = df["size"].astype(int)
            df["timestamp"] = pd.to_datetime(df["timestamp"], format="%d/%b/%Y:%H:%M:%S +0000")
        return df

    except FileNotFoundError:
        print(f"⚠️ File not found: {log_file}")
        return pd.DataFrame()

def detect_malicious_logs(df):
    """Detects malicious activity from structured logs."""
    malicious_entries = []
    
    for _, row in df.iterrows():
        for attack_type, pattern in attack_patterns.items():
            if re.search(pattern, row["request"], re.IGNORECASE):
                malicious_entries.append({**row, "attack_type": attack_type})

    return pd.DataFrame(malicious_entries)

def save_logs(df, file_path):
    """Saves DataFrame to CSV file."""
    if not df.empty:
        df.to_csv(file_path, index=False)
        print(f"✅ Logs saved: {file_path}")
    else:
        print(f"⚠️ No logs to save for: {file_path}")

while True:
    os.system("clear")

    # Parse logs
    parsed_access_logs = parse_log(access_log_file)
    parsed_auth_logs = parse_log(auth_log_file)

    # Combine structured logs
    structured_logs = pd.concat([parsed_access_logs, parsed_auth_logs]).drop_duplicates().reset_index(drop=True)

    # Detect malicious activity
    detected_malicious_logs = detect_malicious_logs(structured_logs)

    # Save logs
    save_logs(structured_logs, structured_logs_file)
    save_logs(detected_malicious_logs, malicious_logs_file)

    # Display logs in a table format
    print("\n📂 Structured Logs:")
    print(tabulate(structured_logs.tail(10), headers="keys", tablefmt="grid"))

    print("\n⚠️ Detected Malicious Logs:")
    print(tabulate(detected_malicious_logs.tail(10), headers="keys", tablefmt="grid"))

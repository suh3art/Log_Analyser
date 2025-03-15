import subprocess
import re

log_file = "../logs/simulated_access.log"

# Attack detection patterns with messages
attack_patterns = {
    "BRUTE_FORCE": (r'POST /login HTTP/1.1" 401', "Multiple failed login attempts detected."),
    "SQL_INJECTION": (r'GET /search\?q=.*(\' OR " OR `)', "SQL Injection attempt detected."),
    "XSS_ATTACK": (r'GET /profile\?name=.*<script>.*</script>', "Cross-Site Scripting (XSS) attempt detected."),
    "ADMIN_ACCESS": (r'GET /admin HTTP/1.1" 403', "Unauthorized attempt to access the admin panel."),
    "PATH_TRAVERSAL": (r'GET /(etc|var|proc)/passwd', "Path Traversal attack attempt detected."),
    "REMOTE_FILE_INCLUSION": (r'GET /index.php\?page=http://', "Remote File Inclusion (RFI) attack detected."),
    "COMMAND_INJECTION": (r'GET /ping\?ip=.*(;|&&|&|`)', "Command Injection attempt detected."),
    "LFI_ATTACK": (r'GET /index.php\?page=\.\./\.\./\.\./', "Local File Inclusion (LFI) attack detected."),
    "USER_ENUMERATION": (r'POST /wp-json/wp/v2/users', "User Enumeration attempt detected."),
    "CSRF_ATTACK": (r'POST /change-email\?email=.*', "Cross-Site Request Forgery (CSRF) attempt detected."),
    "RCE_ATTACK": (r'GET /execute\?cmd=.*', "Remote Code Execution (RCE) attempt detected."),
    "XXE_ATTACK": (r'POST /upload-xml', "XML External Entity (XXE) attack detected."),
    "API_ABUSE": (r'GET /api/user\?username=admin', "Potential API abuse detected.")
}

# Start real-time log monitoring
process = subprocess.Popen(["tail", "-f", log_file], stdout=subprocess.PIPE)

print("🚀 Real-Time Security Monitoring Started...")

for line in iter(process.stdout.readline, b""):
    decoded_line = line.decode("utf-8").strip()

    for attack_type, (pattern, message) in attack_patterns.items():
        if re.search(pattern, decoded_line, re.IGNORECASE):
            print(f"🚨 {attack_type} DETECTED: {message}")
            print(f"🔎 Log Entry: {decoded_line}")
            break  # Stop checking once an attack is identified

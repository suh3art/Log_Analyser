
# 🔥 Security Monitoring System

## 🛡 Overview
This project provides an **automated security monitoring system** that detects **anomalous activities, logs security events, blocks malicious IPs**, and sends **real-time alerts via Discord**.

### 🚀 Features
- **📊 Real-time Log Monitoring**: Analyzes security logs for unusual activity.
- **🧠 Anomaly Detection**: Uses machine learning (`IsolationForest`) and statistical methods (`Z-score`).
- **⛔ Firewall Automation**: Blocks malicious IPs dynamically based on logs.
- **📩 Discord Notifications**: Sends alerts when potential threats are detected.
- **📉 Visual Data Representation**: Uses `asciichartpy` to plot trends.
- **🖥 Cross-Platform Support**: Works on Windows, Linux, and macOS.

## 🏗 Installation
### Prerequisites
Ensure you have **Python 3** installed. Install the dependencies using:
```sh
pip install -r requirements.txt
```
For Linux/macOS, install `iptables` if missing:
```sh
sudo apt install iptables  # Ubuntu/Debian
sudo yum install iptables  # RHEL/CentOS
brew install iptables      # macOS
```

## 🛠 Usage
### 1️⃣ Generate Security Logs
Run the log generator to simulate security events:
```sh
python generatelog.py
```
This creates logs such as `access.log`, `auth.log`, and `attack.log` in the `logs/` folder.

### 2️⃣ Monitor Logs for Threats
Run the **monitoring script** to analyze logs in real time:
```sh
python monitor.py
```
It detects suspicious activity and provides insights into attacks.

### 3️⃣ Parse Logs into Structured Data
```sh
python logparse.py
```
This converts raw logs into structured files:
- `structured_logs.csv` (clean logs)
- `malicious_logs.csv` (potential threats)

### 4️⃣ Detect Anomalies
```sh
python anomalydetect.py
```
This identifies anomalies and generates `anomalous_logs.csv`.

### 5️⃣ Block Malicious IPs
Run the **firewall script** to block attackers:
```sh
python firewallblock.py
```
- Blocks IPs found in `malicious_logs.csv`.
- Automatically unblocks after **10 seconds** (customizable).

### 6️⃣ Enable Discord Alerts
Set up the **Discord bot** for live security notifications:
```sh
python discordbot.py
```
- Configure your **bot token** in `discordbot.py`.
- Receives alerts when anomalies or attacks are detected.

## 📂 Project Structure
```
project-folder/
│-- logs/
│   ├── structured_logs.csv
│   ├── malicious_logs.csv
│   ├── access.log
│   ├── attack.log
│   ├── auth.log
│-- scripts/
│   ├── generatelog.py
│   ├── monitor.py
│   ├── logparse.py
│   ├── anomalydetect.py
│   ├── firewallblock.py
│   ├── discordbot.py
│-- requirements.txt
│-- README.md
```

## ⚙ Configuration
- **Modify time intervals** in `generatelog.py` to control log generation speed.
- **Customize anomaly detection thresholds** in `anomalydetect.py`.
- **Adjust firewall rules** for different operating systems in `firewallblock.py`.

## ⚠ Notes
- 🔄 The script **unblocks IPs after 10 seconds** by default. Change to **600 seconds** for better security.
- 🎛 You can tweak **Z-score thresholds** and **IsolationForest parameters** to improve anomaly detection.
- 🔧 Use `nohup` or `screen` to **run scripts in the background**.

## 💡 Contributing
Contributions are welcome! Feel free to improve detection algorithms, add firewall features, or enhance Discord integration.

## 📜 License
This project is licensed under the **MIT License**.

---
🚀 **Stay ahead of cyber threats with automated security monitoring!** 🔥

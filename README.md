# 🛡️ CyberShield – Cybersecurity Threat Detection & File Protection System

**CyberShield** is a Python-based cybersecurity project designed to detect known malware, monitor file integrity, identify suspicious file changes, generate security alerts, and preserve security evidence.

It integrates **ClamAV** for malware detection and uses **SHA-256 hashing** to verify file integrity. It also provides an approval-based quarantine mechanism to safely isolate detected files without permanently deleting them.

---

## 🚀 Project Objectives

- Detect known malware using ClamAV.
- Scan files and directories for potential threats.
- Monitor important files for unauthorized modifications.
- Verify file integrity using SHA-256 hashes.
- Detect changes to trusted security baselines.
- Generate security alerts.
- Preserve evidence of suspicious file activity.
- Generate JSON-based security reports.
- Provide controlled quarantine with user approval.

## 🧰 Technologies Used

| Technology | Purpose |
|---|---|
| Python 3 | Main programming language |
| ClamAV | Malware detection |
| SHA-256 | File integrity verification |
| Linux / Kali Linux | Development environment |
| Watchdog | Real-time file monitoring |
| JSON | Security report storage |
| Git & GitHub | Version control |

## 📂 Project Structure

```text
CyberShield/
│
├── main.py
├── requirements.txt
├── README.md
│
├── scripts/
│   ├── __init__.py
│   ├── threat_scanner.py
│   ├── quarantine_manager.py
│   ├── threat_report.py
│   ├── baseline_guard.py
│   ├── realtime_monitor.py
│   └── alert_system.py
│
├── test_samples/
├── protected_files/
├── quarantine/
├── backups/
├── evidence/
├── alerts/
├── logs/
└── reports/
```

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone git@github.com:kumarpratham580-hub/CyberShield-.git
```

### 2. Enter the project directory

```bash
cd CyberShield-
```

### 3. Install Python dependencies

```bash
sudo apt update
sudo apt install python3 python3-venv clamav -y
```

### 4. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 5. Install project dependencies

```bash
pip install -r requirements.txt
```

### 6. Update ClamAV database

```bash
sudo apt install clamav-freshclam -y
sudo systemctl enable --now clamav-freshclam
```

ClamAV's background service manages virus database updates.

## ▶️ How to Run

### Run the malware scanner

```bash
python3 -m scripts.threat_scanner
```

### Run the main application

```bash
python3 main.py
```

### Scan a test directory directly

```bash
clamscan --recursive ~/cybershield/test_samples
```

## 🔍 Main Features

### 1. Malware Detection
Uses ClamAV to scan files and identify known malware signatures.

### 2. File Integrity Monitoring
Uses SHA-256 hashing to detect unexpected file modifications.

### 3. Baseline Tamper Detection
Uses a signed baseline to verify that trusted baseline data has not been modified.

### 4. Real-Time File Monitoring
Uses Python Watchdog to monitor file creation, modification, deletion, and movement.

### 5. Security Alerts
Generates alerts when suspicious file activity is detected.

### 6. Safe Quarantine
Copies approved detected files into a restricted quarantine folder and verifies the copied file using SHA-256. The current implementation preserves the original file.

### 7. Security Reports
Stores scan results and threat information in JSON format.

## 🧪 Example Output

```text
===================================
     CYBERSHIELD THREAT SCANNER
===================================

[INFO] Starting ClamAV scan...
[TARGET] test_samples

========== SCAN RESULTS ==========
[SAFE] No threats detected.

[REPORT SAVED] reports/threat_report.json

========== FINAL SUMMARY ==========
Threats detected: 0
Quarantine copies verified: 0
Original files were not removed.
```

## 📊 Example Use Case

Suppose a user downloads a suspicious file.

1. CyberShield scans the file using ClamAV.
2. ClamAV checks it against its malware detection signatures.
3. If a known threat is detected, CyberShield displays the detection name.
4. The user can approve copying the file into quarantine.
5. SHA-256 verifies the quarantine copy.
6. CyberShield records the result in a JSON report.

**Note:** Quarantine in the current implementation copies the file; it does not remove or disable the original.

## 🔐 Security Approach

- User approval before quarantine.
- SHA-256 file verification.
- Restricted quarantine directory permissions.
- Security event logging.
- Evidence preservation.
- No automatic permanent deletion.

## ⚠️ Limitations

- ClamAV cannot guarantee detection of every malware sample.
- False positives and unknown threats are possible.
- The current quarantine workflow preserves the original file.
- The project is an educational security tool, not a replacement for enterprise endpoint protection.

## 🔮 Future Enhancements

- Graphical user interface (GUI).
- Email and desktop security notifications.
- Advanced vulnerability assessment.
- Suspicious process monitoring.
- Package security auditing.
- Improved automated remediation with user approval.
- Dashboard for security reports.

## 📜 Disclaimer

CyberShield is developed for educational purposes and authorized security testing only. Use it only on systems and files you own or have permission to inspect.

---

**CyberShield – Detect Threats. Protect Files. Preserve Evidence.**

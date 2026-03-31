<div align="center">

# 🛡️ SentinelLite
### AI-Powered SOC Automation System for Real-Time Threat Detection and Response

[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Suricata](https://img.shields.io/badge/Suricata-EF3B2D?style=for-the-badge)](https://suricata.io)
[![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg?style=for-the-badge)](LICENSE)

> A lightweight Security Operations Center (SOC) automation tool that integrates real IDS telemetry, machine learning classification, and automated response — designed to run even on constrained mobile hotspot environments.

</div>

---

## 📌 What Problem Does This Solve?

Most organizations can't afford enterprise SIEM tools like Splunk or IBM QRadar. **SentinelLite** is a proof-of-concept SOC automation system that shows how open-source tools + Python + ML can replicate core SOC analyst workflows:

- **Detect** → Suricata watches live network traffic and fires alerts
- **Classify** → A trained Random Forest model categorizes the threat type
- **Respond** → The system auto-blocks malicious IPs via `iptables`
- **Report** → A GUI dashboard shows live alerts and daily summaries

---

## 🚀 Key Features

| Feature | Description |
|---------|-------------|
| 🔍 Real-Time IDS | Suricata monitors live traffic and writes to `eve.json` |
| 🧠 ML Classification | Random Forest model classifies alert categories |
| 🔐 Auto IP Blocking | Malicious IPs blocked instantly via `iptables` |
| 🔔 Push Notifications | Desktop alerts via `notify2` + Telegram integration |
| 📊 GUI Dashboard | Tkinter interface for live monitoring and alert history |
| 🧾 CSV Logging | Persistent logs with daily summary report generation |
| 📡 Hotspot Tested | Validated under real bandwidth constraints (mobile hotspot) |

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| IDS Engine | Suricata |
| Language | Python 3.10+ |
| ML Model | scikit-learn — Random Forest Classifier |
| GUI | Tkinter |
| Web Dashboard | Flask |
| Auto Response | iptables |
| Notifications | notify2, Telegram Bot API |
| Packaging | virtualenv / Docker (optional) |

---

## 📁 Project Structure

```
SentinelLite/
├── src/
│   ├── main.py              # Entry point — starts all modules
│   ├── alert_engine.py      # Parses Suricata eve.json alerts
│   ├── responder.py         # Auto IP blocking via iptables
│   └── notifier.py          # Desktop + Telegram notifications
├── gui/
│   └── dashboard.py         # Tkinter GUI for live monitoring
├── utils/
│   ├── logger.py            # CSV log writer
│   └── reporter.py          # Daily summary report generator
├── model.pkl                # Trained Random Forest model
├── vectorizer.pkl           # Feature vectorizer
├── requirements.txt
├── .gitignore
└── README.md
```

---

## ⚙️ Installation & Setup

### Prerequisites
- Ubuntu / Kali Linux (or any Debian-based OS)
- Python 3.10+
- Suricata installed and running
- Root/sudo access (for iptables)

### 1. Clone the Repository
```bash
git clone https://github.com/Aceknight4/SentinelLite.git
cd SentinelLite
```

### 2. Create Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Install and Configure Suricata
```bash
sudo apt update && sudo apt install suricata -y
sudo nano /etc/suricata/suricata.yaml
# Set your network interface (e.g., wlp2s0)
# Enable eve.json output under logging
```

### 5. Start Suricata
```bash
sudo systemctl enable suricata
sudo systemctl start suricata
```

### 6. Run SentinelLite
```bash
sudo python3 src/main.py
```

---

## 🧪 Simulated Attacks Used in Testing

All attacks were simulated from a separate **Kali Linux** machine over a mobile hotspot:

| Attack Type | Tool | Command Example |
|------------|------|----------------|
| Port Scan | Nmap | `nmap -sS -Pn <target_ip>` |
| SSH Brute Force | Hydra | `hydra -l root -P rockyou.txt ssh://<target_ip>` |
| DoS Flood | hping3 | `hping3 -S --flood -p 80 <target_ip>` |
| Reverse Shell | Metasploit | `msfvenom` payload + listener |

---

## 📋 How It Works (Simple Explanation)

```
Network Traffic
      │
      ▼
  Suricata IDS
  (eve.json alerts)
      │
      ▼
  alert_engine.py
  (reads + parses alerts)
      │
      ├──► ML Model → Classifies threat type
      │
      ├──► responder.py → Blocks IP via iptables
      │
      ├──► notifier.py → Desktop + Telegram alert
      │
      └──► logger.py → Saves to CSV log
                │
                ▼
          Tkinter GUI Dashboard
          (live view + history)
```

---

## 🎯 Project Context

This is my **Final Year Project** for a B.Tech in Network & Security at the Catholic University Institute of Buea (CUIB). The goal was to demonstrate that a capable, automated SOC system can be built with open-source tools on a limited budget — making security automation accessible to small organizations.

---

## 👤 Author

**Seppo Anel Graph Mbake**  
SOC Analyst | Blue Team Engineer | ISO 27001 Certified  
📧 [annelgraph46@gmail.com](mailto:annelgraph46@gmail.com)  
🔗 [LinkedIn](https://linkedin.com/in/seppo-anel-graph-mbake-03b736206)  
💻 [GitHub](https://github.com/Aceknight4)

---

## 📄 License

This project is licensed under the GPL-3.0 License — see [LICENSE](LICENSE) for details.

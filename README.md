# 🛡️ AI-Powered SOC Automation System

A real-time Security Operations Center (SOC) automation tool powered by Suricata IDS, Python, and Machine Learning. Designed for detecting, classifying, and responding to threats over a mobile hotspot network.

---

## 🚀 Features

- ✅ Real-time intrusion detection using Suricata
- 🧠 ML-based alert classification (Random Forest)
- 🔐 Auto IP blocking using `iptables`
- 🔔 Desktop notifications with `notify2`
- 📈 Tkinter GUI for live alert monitoring
- 🧾 CSV logging and daily summary reports
- 📡 Tested over mobile hotspot with Kali Linux attacks

---

## 🛠️ Tech Stack

| Component | Technology |
|----------|------------|
| IDS      | Suricata   |
| Language | Python 3.10+ |
| ML       | scikit-learn, joblib |
| GUI      | Tkinter |
| Response | iptables |
| Notifications | notify2 / Telegram |
| Packaging | virtualenv / Docker (optional) |

---

## 📦 Installation

### 1. Clone the Repository

```bash
git clone <repo-url>
cd soc_automation
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
sudo apt update && sudo apt install suricata
sudo nano /etc/suricata/suricata.yaml
# Set interface (e.g., wlp2s0) and enable eve.json logging
```

### 5. Start Suricata

```bash
sudo systemctl enable suricata
sudo systemctl start suricata
```

### 6. Run Main Script

```bash
python main.py
```

---

## 📊 Simulated Attacks (from Kali Linux)

| Tool | Command |
|------|---------|
| Nmap Scan | `nmap -sS -Pn <victim_ip>` |
| Hydra (SSH Brute Force) | `hydra -l root -P rockyou.txt ssh://<victim_ip>` |
| hping3 (DoS) | `hping3 -S --flood -p 80 <victim_ip>` |
| Reverse Shell | `msfvenom`, `wget`, `./shell.elf` |

---

## 📁 Folder Structure

```
soc_automation/
├── main.py
├── responder.py
├── alert_engine.py
├── notifier.py
├── gui.py
├── utils.py
├── model.pkl
├── vectorizer.pkl
├── requirements.txt
├── logs/
└── README.md
```

---

## 📘 License

This project is for academic and non-commercial research use. All rights reserved by the author.

---

## 👤 Author

**Seppo Anel Graph Mbake**  
Student, Network & Security  
CUIB – Catholic University Institute of Buea  
Email: anelgraph46@gmail.com  

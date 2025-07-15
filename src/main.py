import json
import os
import time
import notify2
import joblib
import pandas as pd
from responder import block_ip
from utils import (
    log_incident,
    extract_features,
    is_new_alert,
    ensure_log_file
)

# === Config Paths ===
EVE_JSON = "/var/log/suricata/eve.json"
MODEL_PATH = "model.pkl"
VECTORIZER_PATH = "vectorizer.pkl"
LOG_FILE = "/var/log/soc_automation/incident_report.csv"
OFFSET_FILE = "/var/log/soc_automation/.last_offset"

# === Setup ===
try:
    notify2.init("SOC Notifier")
    notifications_enabled = True
except Exception as e:
    print("⚠️ Notifications disabled (DBus error):", e)
    notifications_enabled = False

ensure_log_file(LOG_FILE)

try:
    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    print("✅ ML model and vectorizer loaded.")
except Exception as e:
    print(f"❌ Failed to load model/vectorizer: {e}")
    model = None
    vectorizer = None

# Track processed flow_ids
PROCESSED_IDS = set()

SIGNATURE_OVERRIDES = [
    "ET SCAN Nmap",
    "ET SCAN Potential SSH",
    "Brute Force",
    "Reverse Shell",
    "Ping Flood",
    "MALWARE",
    "SQL Injection",
    "ET EXPLOIT"
]

def send_notification(message):
    if notifications_enabled:
        n = notify2.Notification("🚨 Threat Detected", message, "dialog-warning")
        n.set_urgency(notify2.URGENCY_CRITICAL)
        n.show()

def classify_alert(alert):
    alert_msg = alert["alert"]["signature"]
    for keyword in SIGNATURE_OVERRIDES:
        if keyword.lower() in alert_msg.lower():
            print(f"[OVERRIDE] '{alert_msg}' matched override rule → attack")
            return "attack"

    features = extract_features(alert)
    df = pd.DataFrame([features])
    try:
        if vectorizer:
            df = vectorizer.transform(df)
        if model:
            return model.predict(df)[0]
    except Exception as e:
        print(f"⚠️ ML prediction failed: {e}")
    return "unknown"

def load_last_offset():
    if os.path.exists(OFFSET_FILE):
        with open(OFFSET_FILE, "r") as f:
            try:
                return int(f.read().strip())
            except ValueError:
                return 0
    return 0

def save_last_offset(offset):
    with open(OFFSET_FILE, "w") as f:
        f.write(str(offset))

def print_report_summary():
    if not os.path.exists(LOG_FILE):
        print("\n❌ No report to summarize.")
        return

    df = pd.read_csv(LOG_FILE)
    if df.empty:
        print("\n📭 No data yet.")
        return

    df['Date'] = pd.to_datetime(df['Timestamp']).dt.date

    print("\n📅 Alerts by Day:")
    print(df.groupby('Date').size())

    print("\n🕵️ Alerts by Source IP:")
    print(df['Source IP'].value_counts())

    print("\n🧭 Alerts by Signature:")
    print(df['Alert Signature'].value_counts())

    print("\n📊 Summary Table:")
    summary = df.groupby(['Date', 'Source IP', 'Alert Signature']).size().reset_index(name='Count')
    print(summary.to_string(index=False))

def monitor_recent_alerts():
    print("🔁 Monitoring for recent alerts only...")
    while True:
        try:
            if not os.path.exists(EVE_JSON):
                print("❌ Suricata eve.json not found.")
                time.sleep(5)
                continue

            last_offset = load_last_offset()
            with open(EVE_JSON, "r") as f:
                f.seek(last_offset)
                lines = f.readlines()
                save_last_offset(f.tell())

            for line in lines:
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        alert_id = event.get("flow_id")
                        if is_new_alert(alert_id, PROCESSED_IDS):
                            PROCESSED_IDS.add(alert_id)

                            prediction = classify_alert(event)
                            src_ip = event["src_ip"]
                            dest_ip = event["dest_ip"]
                            alert_msg = event["alert"]["signature"]
                            category = event["alert"].get("category", "Uncategorized")
                            timestamp = event["timestamp"]

                            print(f"[ALERT] {alert_msg} | {src_ip} → {dest_ip} | Class: {prediction}")

                            if prediction == "attack":
                                message = f"🚨 {category}\n{alert_msg}\n{src_ip} → {dest_ip}\nClass: {prediction.upper()}"
                                send_notification(message)
                                block_ip(src_ip, alert_msg)
                                log_incident(timestamp, src_ip, dest_ip, alert_msg, prediction, LOG_FILE)
                            else:
                                print(f"ℹ️ Alert ignored: {alert_msg} | Class = {prediction}")

                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(f"⚠️ Error processing alert: {e}")

            print_report_summary()
            time.sleep(10)

        except KeyboardInterrupt:
            print("\n🛑 Monitoring stopped by user.")
            break
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    monitor_recent_alerts()

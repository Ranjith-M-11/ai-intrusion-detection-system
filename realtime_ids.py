from scapy.all import sniff, IP, TCP, UDP
import joblib
import datetime
import pandas as pd
import smtplib
from email.mime.text import MIMEText
from win11toast import toast   # ✔ stable popup library

# Load trained AI model
model = joblib.load("ids_model.pkl")
LOG_FILE = "ids_alerts.log"


# ========================= EMAIL ALERT (MAILTRAP) =========================
def send_email_alert(message):
    smtp_server = "sandbox.smtp.mailtrap.io"
    smtp_port = 2525
    smtp_username = "18c9bb17bfee79"
    smtp_password = "97c79c0bf32ca6"

    sender = "alert@ids-system.com"
    receiver = "report@ids-system.com"

    msg = MIMEText(message)
    msg["Subject"] = "⚠ IDS ALERT: Intrusion Detected"
    msg["From"] = sender
    msg["To"] = receiver

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.login(smtp_username, smtp_password)
        server.sendmail(sender, [receiver], msg.as_string())
        server.quit()
        print("✔ Email alert sent (Mailtrap Sandbox)")
    except Exception as e:
        print("❌ Email sending failed:", e)


# ========================= POPUP ALERT =========================
def popup_alert(message):
    try:
        toast("⚠ IDS ALERT", message)
    except Exception as e:
        print("Popup failed:", e)


# ========================= LOG SAVE =========================
def log_alert(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.datetime.now().isoformat()} - {msg}\n")


# ========================= FEATURE EXTRACTION =========================
def extract_features(pkt):
    proto = 0
    sport = 0
    dport = 0
    length = len(pkt)

    if IP in pkt:
        proto = pkt[IP].proto
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

    return [proto, sport, dport, length]


# ========================= PACKET PROCESSING =========================
def process_packet(pkt):
    if IP not in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst

    features = extract_features(pkt)
    df = pd.DataFrame([features], columns=["proto", "sport", "dport", "length"])
    prediction = model.predict(df)[0]

    if prediction == 1:
        alert_msg = f"⚠ Intrusion detected from {src} to {dst} | features={features}"
        print(alert_msg)

        log_alert(alert_msg)
        send_email_alert(alert_msg)
        popup_alert(alert_msg)

    else:
        print(f"OK {src} -> {dst}")


# ========================= START IDS =========================
send_email_alert("Test alert: IDS Mailtrap email system is working.")
popup_alert("Test popup: IDS popup working.")

print("Starting AI-Based IDS with Alerts... Press Ctrl+C to stop.")
sniff(prn=process_packet, store=False)

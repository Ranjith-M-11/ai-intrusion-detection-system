🚨 AI-Based Intrusion Detection System (IDS)

Real-Time Packet Monitoring • Machine Learning Detection • Email Alerts • System Notifications

<p align="center"> <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge" /> <img src="https://img.shields.io/badge/Scapy-Network%20Sniffer-yellow?style=for-the-badge" /> <img src="https://img.shields.io/badge/ML-RandomForest-green?style=for-the-badge" /> <img src="https://img.shields.io/badge/Alerts-Mailtrap%20SMTP-orange?style=for-the-badge" /> <img src="https://img.shields.io/badge/Platform-Windows11-purple?style=for-the-badge" /> </p>

A cutting-edge AI-powered Intrusion Detection System that captures real-time network packets, extracts protocol-level features, classifies traffic using a Machine Learning model, and triggers:

🔔 Windows toast notifications

📧 Instant email alerts (Mailtrap Sandbox)

📜 Intrusion logs

🧠 ML-based anomaly detection

Built using Python, Scapy, Scikit-learn, Pandas, and win11toast.


🧠 Features

    FeatureDescription

        📡 Live Packet Sniffing	         Real-time network monitoring using Scapy
        
        🧠 ML Classification	           RandomForest model detects anomalies
        
        📊 Feature Extraction	           Protocol, ports, packet size
        
        🔔 Notifications	               Windows toast popup alerts
        
        📧 Email Alerts	                 Using Mailtrap secure SMTP sandbox
        
        📝 Logging	                     Every intrusion recorded in ids_alerts.log
        
        🛠 Modular Design	               Collector → Trainer → Real-time IDS
        
        🖥 Cross-compatible	             Works on any Windows machine


🏗 System Architecture

    flowchart TD
        A[Live Network Traffic] --> B[Packet Sniffer (Scapy)]
        B --> C[Feature Extractor]
        C --> D[Random Forest Model]
        D -->|Normal| E[Console Output]
        D -->|Intrusion| F[Alert Layer]
        F --> F1[Windows Popup]
        F --> F2[Mailtrap Email]
        F --> F3[ids_alerts.log]


🔬 Detection Pipeline

    sequenceDiagram
        Participant N as Network Packet
        Participant S as Scapy Sniffer
        Participant F as Feature Extractor
        Participant M as ML Model
        Participant A as the Alert System

        N->>S: Capture packet
        S->>F: Send raw packet
        F->>M: Extract features & classify
        M-->>A: Return prediction (0/1)
        A->>A: Log + Popup + Email (if intrusion)


📁 Project Structure

    📦 ai-intrusion-detection-system
         ┣ 📜 basic_sniffer.py          # Simple packet sniffer
         ┣ 📜 data_collector.py         # Capture & save features to CSV
         ┣ 📜 train_model.py            # Train RandomForest ML model
         ┣ 📜 realtime_ids.py           # Real-time IDS with alerts
         ┣ 📜 ids_alerts.log            # Intrusion logs (auto-created)
         ┣ 📜 network_data.csv          # Training data (optional)


🔧 Installation

1️⃣ Clone the repository

    git clone https://github.com/Ranjith-M-11/ai-intrusion-detection-system
    cd ai-intrusion-detection-system

2️⃣ Install dependencies

    pip install -r requirements.txt

3️⃣ Install Npcap (required for Scapy on Windows)

    Download: https://npcap.com/#download

📊 Training the Machine Learning Model

  Collect packet data:

      py data_collector.py
     
  Train model:

      py train_model.py

This generates:

      ids_model.pkl

This is the AI brain of your IDS.

🚨 Running the Real-Time IDS

      py realtime_ids.py

The system will:
 
 ✔ Monitor all packets

 ✔ Classify traffic
 
 ✔ Show OK / Intrusion logs
 
 ✔ Send email alert
 
 ✔ Show desktop popup
 
 ✔ Log intrusions to a file.


📧 Email Alert Preview (Mailtrap)

      Subject: ⚠ IDS ALERT: Intrusion Detected

      Intrusion detected from 192.168.1.20 to 192.168.1.10
      Features = [6, 44321, 80, 596]


💻 Desktop Popup Alert Preview

      ⚠ IDS ALERT
      Intrusion detected from 192.168.1.20 to 192.168.1.10


📗 Sample Console Output

      OK 10.54.232.129 -> 34.230.135.94
      ⚠ Intrusion detected from 192.168.1.15 to 192.168.1.10 | features=[6, 44565, 80, 590]
      ✔ Email alert sent (Mailtrap Sandbox)


🚀 Future Enhancements

Add a Web UI dashboard

Add port-scan detection module

Add DoS attack detection

Add IP blocking (auto-firewall updates)

Migrate to deep learning models

Monitor multiple devices (distributed IDS)


🧰 Tech Stack Icons
<p align="left"> <img src="https://skillicons.dev/icons?i=python,github,git" /> <img src="https://img.shields.io/badge/Scapy-%20Packet%20Sniffer-yellow?style=flat-square" /> <img src="https://img.shields.io/badge/RandomForest-ML-green?style=flat-square" /> <img src="https://img.shields.io/badge/Mailtrap-SMTP-orange?style=flat-square" /> </p> 

❤️ Support

If you like this project, consider giving it a ⭐ star on GitHub!

⭐ Contribute

PRs are welcome. Fork this repo, improve, and open a pull request.

# 🛡️ NetGuard: AI-Driven Real-Time Network Threat Monitor

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Streamlit](https://img.shields.io/badge/Frontend-Streamlit-red)
![Scapy](https://img.shields.io/badge/Network-Scapy-green)
![Status](https://img.shields.io/badge/Status-Active-success)

## 📌 Project Overview
**NetGuard** is a lightweight, real-time Network Intrusion Detection System (NIDS) designed to bridge the gap between passive monitoring and automated threat detection. Unlike traditional signature-based tools, NetGuard leverages **Unsupervised Machine Learning (Isolation Forest)** to detect statistical anomalies in live network traffic.

It captures packets in real-time, parses metadata (Source/Destination IP, Protocol, Size), and visualizes the network posture on an interactive dashboard.

---

## 🚀 Key Features
- **Real-Time Packet Sniffing:** Captures live IP traffic (TCP, UDP, ICMP) using `Scapy`.
- **AI-Powered Anomaly Detection:** Uses an **Isolation Forest** model to flag outlier packets based on size and frequency.
- **Interactive Dashboard:** Dynamic charts built with **Streamlit** & **Plotly** to visualize protocol distribution and traffic volume.
- **Live Threat Alerts:** Instant visual feedback when suspicious traffic is detected.
- **Lightweight Architecture:** Uses threading to separate data ingestion from visualization, ensuring zero lag.

---

## 🛠️ Tech Stack
- **Language:** Python 3.9+
- **Network Engine:** Scapy
- **Data Processing:** Pandas
- **Machine Learning:** Scikit-Learn (Isolation Forest)
- **Visualization:** Streamlit, Plotly Express

---

## ⚙️ Installation & Setup

### Prerequisites
- Python 3.9 or higher installed.
- Administrator/Root privileges (required for packet sniffing).


### 1. Clone the repository
```bash
git clone https://github.com/aman01k/NetGuard-AI-Driven-Real-Time-Network-Threat-Monitor.git
cd NetGuard-AI-Driven-Real-Time-Network-Threat-Monitor
```

### 2. Install dependencies
```bash
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Start the dashboard
Packet capture needs administrator rights, so start Streamlit with them:

```bash
# macOS / Linux
sudo venv/bin/streamlit run dashboard.py
```

On Windows, install [Npcap](https://npcap.com/) first, then run `streamlit run dashboard.py` from a terminal opened as Administrator.

The dashboard opens at http://localhost:8501.

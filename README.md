# NETWORK-INTRUSION-DETECTION-SYSTEM-USING-MACHINE-LEARNING-PFA

<p align="center">
  <em>Detect Threats Faster, Stay Secure and Safe</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/last%20commit-today-brightgreen" />
  <img src="https://img.shields.io/badge/java-41.5%25-blue" />
  <img src="https://img.shields.io/badge/languages-7-informational" />
</p>

<p align="center">
  <em>Built with the tools and technologies:</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Flask-black?logo=flask" />
  <img src="https://img.shields.io/badge/JSON-black?logo=json" />
  <img src="https://img.shields.io/badge/Markdown-black?logo=markdown" />
  <img src="https://img.shields.io/badge/scikit-learn-orange?logo=scikit-learn" />
  <img src="https://img.shields.io/badge/Gradle-02303A?logo=gradle" />
  <img src="https://img.shields.io/badge/XML-0060ac?logo=xml" />
  <img src="https://img.shields.io/badge/Python-3776AB?logo=python" />
  <img src="https://img.shields.io/badge/bat-4B4B77?logo=windows-terminal" />
  <img src="https://img.shields.io/badge/pandas-150458?logo=pandas" />
</p>

---

## 🌟 Overview

This project is my End-Of-Year Project (PFA) for my 4th year of engineering as a cybersecurity student at ENSIASD. It implements an advanced, modular Network Traffic Analysis and Intrusion Detection System (IDS) for Linux environments. The system leverages signature-based detection (Snort 3), behavioral analysis (Machine Learning), and flow-based monitoring (CICFlowMeter) to deliver comprehensive, real-time network security. An intuitive web dashboard provides live monitoring, alert management, and historical insights.

## 🚀 Key Features

- **Real-time Traffic Capture:** Continuous monitoring with tcpdump
- **Multi-layered Detection:**
  - Signature-based detection (Snort 3)
  - Behavioral anomaly detection (XGBoost, PCA)
  - Flow-based feature extraction (CICFlowMeter)
- **Automated Alerting:** Email notifications and detailed alert history
- **Web Dashboard:** Real-time and historical data visualization, alert management
- **Modular & Extensible:** Easily adaptable for research or production

## 🛠️ Technology Stack

- **Languages & Frameworks:** Python 3.8+, Java (for CICFlowMeter), Flask
- **Security Tools:** Snort 3, CICFlowMeter
- **Machine Learning:** XGBoost, scikit-learn, pandas
- **Other:** watchdog, joblib, python-dateutil

## 📋 Prerequisites

- Linux-based OS (tested on Kali Linux)
- Root/sudo privileges
- Snort 3 installed and configured
- Java Runtime Environment (for CICFlowMeter)
- Python 3.8 or higher

## 🚀 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/MOHAMEDBOUTALMAOUINE/Network-Intrusion-Detection-System-Using-Machine-Learning-PFA.git
   cd Network-Intrusion-Detection-System-Using-Machine-Learning-PFA
   ```

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Snort:**
   ```bash
   sudo cp /etc/snort/snort.lua /etc/snort/snort.lua.backup
   sudo cp /etc/snort/rules/local.rules /etc/snort/rules/local.rules.backup
   ```

4. **Setup CICFlowMeter:**
   - Download and build from [CICFlowMeter GitHub](https://github.com/ahlashkari/CICFlowMeter).
   - Ensure Java is installed and accessible.

5. **Add ML models to `Models&&scaler&&PCA/`:**
   - `scaler.pkl`
   - `pca.pkl`
   - `Multi_classification_XGBoost_depth_6.pkl`

## 💻 How to Run

> **Open three terminal windows as root and run the following:**

### Terminal 1 – Main System
```bash
sudo python3 main.py
```
Handles: traffic capture, Snort analysis, web dashboard

### Terminal 2 – ML Processor
```bash
sudo python3 ml_processor.py
```
Handles: flow processing, anomaly detection, ML predictions

### Terminal 3 – Alert System
```bash
sudo python3 gmail_alert.py
```
Handles: alert processing, email notifications, alert history

## 📊 System Architecture

1. **Traffic Capture:**  
   Real-time packet capture with tcpdump, automatic file rotation.
2. **Analysis Pipeline:**  
   Snort 3 for signature detection, CICFlowMeter for flow extraction, ML for anomaly detection.
3. **Alert Management:**  
   Email notifications, alert logging, and history.
4. **Web Dashboard:**  
   Live monitoring, historical data, and alert management.

## 📁 Directory Structure

- `pcap_captures/` – Captured PCAP files
- `snort_alerts/` – Snort alert JSON files
- `flow_features/` – Flow features CSVs
- `results/` – ML prediction results
- `Models&&scaler&&PCA/` – ML model files
- `logs/` – System logs
- `templates/` – Web templates
- `static/` – Static assets

## 🔒 Security Features

- Real-time traffic analysis
- Multi-method detection
- Automated, secure alerting
- Comprehensive logging and monitoring

## 📝 License

MIT License

## 👥 Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## ⚠️ Disclaimer

This tool is for research and educational purposes only. Ensure compliance with all applicable laws and regulations regarding network monitoring and data collection.

## 📧 Contact

For questions or collaboration, contact:  
**mohamed.boutalmaouine.78@edu.uiz.ac.ma**

## 🎥 Démo Vidéo (Port Scan attack Simulation)

👉 [Click here to view the demonstration video](https://drive.google.com/file/d/11VhkVG5dkBX1w8mwvGNJWlq3zAV8k6Fn/view?usp=drive_link)

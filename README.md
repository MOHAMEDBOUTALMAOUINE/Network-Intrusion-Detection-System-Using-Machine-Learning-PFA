# NETWORK-INTRUSION-DETECTION-SYSTEM-USING-MACHINE-LEARNING-PFA

<p align="center">
  <em>Detect Threats Faster, Stay Secure Smarter</em>
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

This is my End-Of-Year Project (PFA) for my 4th year of engineering as a cybersecurity student at ENSIASD. The project implements an advanced Network Traffic Analysis and Intrusion Detection System that combines signature-based detection (Snort 3), behavioral analysis (Machine Learning), and flow-based monitoring (CICFlowMeter) to provide comprehensive network security in Linux environments. The system features real-time traffic analysis, automated threat detection, and an intuitive web-based dashboard for security monitoring and alert management.

## 🚀 Key Features

- **Real-time Traffic Capture**: Continuous network traffic monitoring using tcpdump
- **Multi-layer Analysis**:
  - Signature-based detection with Snort 3
  - Behavioral analysis using Machine Learning (XGBoost, PCA)
  - Flow-based feature extraction with CICFlowMeter
- **Automated Alert System**:
  - Email notifications for critical alerts
  - Detailed alert logging and history
- **Web Interface**:
  - Real-time monitoring dashboard
  - Historical data visualization
  - Alert management system

## 🛠️ Technical Stack

- **Core Technologies**:
  - Python 3.8+
  - Snort 3
  - CICFlowMeter
  - XGBoost
  - Flask

- **Key Dependencies**:
  - pandas >= 1.3.0
  - scikit-learn >= 0.24.2
  - joblib >= 1.0.1
  - watchdog >= 2.1.0
  - Flask >= 2.0.1
  - python-dateutil >= 2.8.2

## 📋 Prerequisites

- Linux-based operating system (tested on Kali Linux)
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

2. **Install required Python packages:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Snort:**
   ```bash
   sudo cp /etc/snort/snort.lua /etc/snort/snort.lua.backup
   sudo cp /etc/snort/rules/local.rules /etc/snort/rules/local.rules.backup
   ```

4. **Setup CICFlowMeter:**
   - Download and build CICFlowMeter from [CICFlowMeter GitHub](https://github.com/ahlashkari/CICFlowMeter).
   - Ensure Java is installed and accessible from your terminal.

5. **Place your ML models in the `Models&&scaler&&PCA/` directory:**
   - scaler.pkl
   - pca.pkl
   - Multi_classification_XGBoost_depth_6.pkl

## 💻 Running the System

The system requires **three terminal windows** running as root. Open three terminals and run the following commands:

### Terminal 1 - Main System
```bash
sudo python3 main.py
```
Handles:
- Network traffic capture
- Snort analysis
- Web interface

### Terminal 2 - ML Processor
```bash
sudo python3 ml_processor.py
```
Handles:
- Network flow processing
- Anomaly detection
- ML predictions

### Terminal 3 - Alert System
```bash
sudo python3 gmail_alert.py
```
Handles:
- Security alert processing
- Email notifications
- Alert history

## 📊 System Architecture

1. **Traffic Capture Module:**  
   Real-time packet capture using tcpdump, automatic file rotation and management.

2. **Analysis Pipeline:**  
   Snort-based signature detection, CICFlowMeter flow analysis, machine learning-based anomaly detection.

3. **Alert Management:**  
   Email notification system, alert logging and storage, alert history tracking.

4. **Web Interface:**  
   Real-time monitoring dashboard, historical data analysis, alert management interface.

## 📁 Directory Structure

- `pcap_captures/` - PCAP files from tcpdump
- `snort_alerts/` - Snort alert JSON files
- `flow_features/` - Flow features CSV files
- `results/` - ML prediction results
- `Models&&scaler&&PCA/` - ML model files
- `logs/` - System logs
- `templates/` - Web interface templates
- `static/` - Static web assets

## 🔒 Security Features

- Real-time traffic analysis
- Multiple detection methods
- Automated alert system
- Detailed logging and monitoring
- Secure alert delivery

## 📝 License

MIT License

## 👥 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## ⚠️ Disclaimer

This tool is designed for security research and network monitoring purposes only. Users are responsible for ensuring compliance with local laws and regulations regarding network monitoring and data collection.

## 📧 Contact

mohamed.boutalmaouine.78@edu.uiz.ac.ma

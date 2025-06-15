# 🛡️ Advanced Network Traffic Analysis & Intrusion Detection System

## 🌟 Overview
This project implements a sophisticated Network Traffic Analysis and Intrusion Detection System that combines multiple security tools and machine learning techniques to provide real-time network monitoring and threat detection. The system processes network traffic, analyzes it using both signature-based and behavioral detection methods, and provides detailed insights through a web interface.

## 🚀 Key Features

- **Real-time Traffic Capture**: Continuous network traffic monitoring using tcpdump
- **Multi-layer Analysis**:
  - Signature-based detection using Snort 3
  - Behavioral analysis using machine learning
  - Flow-based analysis with PyFlowMeter
- **Advanced ML Detection**:
  - XGBoost-based classification
  - PCA for feature reduction
  - Comprehensive feature extraction
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
  - PyFlowMeter
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
- Network interface with monitoring capabilities
- Python 3.8 or higher

## 🚀 Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd [repository-name]
```

2. Install required Python packages:
```bash
pip install -r requirements.txt
```

3. Configure Snort:
```bash
sudo cp /etc/snort/snort.lua /etc/snort/snort.lua.backup
sudo cp /etc/snort/rules/local.rules /etc/snort/rules/local.rules.backup
```

4. Setup PyFlowMeter:
```bash
cd pyflowmeter
python -m venv pyflowmeter_env
source pyflowmeter_env/bin/activate
pip install -r requirements.txt
```

5. Place your ML models in the `Models&&scaler&&PCA/` directory:
   - scaler.pkl
   - pca.pkl
   - Multi_classification_XGBoost_depth_6.pkl

## 💻 Running the System

The system requires three terminal windows running as root. Open three terminal windows and run the following commands:

### Terminal 1 - Main System
```bash
sudo python3 main.py
```
This starts the main system which handles:
- Network traffic capture
- Snort analysis
- Web interface

### Terminal 2 - ML Processor
```bash
sudo python3 ml_processor.py
```
This runs the machine learning component which:
- Processes network flows
- Performs anomaly detection
- Generates predictions

### Terminal 3 - Alert System
```bash
sudo python3 gmail_alert.py
```
This manages the alert system which:
- Processes security alerts
- Sends email notifications
- Maintains alert history

## 📊 System Architecture

The system follows a modular architecture with the following components:

1. **Traffic Capture Module**:
   - Real-time packet capture using tcpdump
   - Automatic file rotation and management

2. **Analysis Pipeline**:
   - Snort-based signature detection
   - PyFlowMeter flow analysis
   - Machine learning-based anomaly detection

3. **Alert Management**:
   - Email notification system
   - Alert logging and storage
   - Alert history tracking

4. **Web Interface**:
   - Real-time monitoring dashboard
   - Historical data analysis
   - Alert management interface

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

[Your contact information]

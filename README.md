# Network Traffic Analysis System

This system provides real-time network traffic monitoring, analysis, and visualization using a combination of tools including tcpdump, Snort 3, PyFlowMeter, and machine learning.

## Features

- Real-time network traffic capture using tcpdump
- Intrusion detection using Snort 3
- Network flow feature extraction using PyFlowMeter
- Machine learning-based traffic classification using XGBoost
- Web-based visualization dashboard

## Prerequisites

- Python 3.8+
- tcpdump
- Snort 3
- PyFlowMeter (with virtual environment)
- Required Python packages (see requirements.txt)

## Installation

1. Clone this repository
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Ensure Snort 3 is installed and configured:
   - Configuration file: `/etc/snort/snort.lua`
   - Local rules: `/etc/snort/rules/local.rules`

4. Setup PyFlowMeter:
   - Ensure PyFlowMeter is installed at `~/Desktop/PFA - IDS+ML/pyflowmeter/`
   - Activate the virtual environment:
     ```bash
     source ~/Desktop/PFA - IDS+ML/pyflowmeter/pyflowmeter_env/bin/activate
     ```

5. Place your ML models in the `Models&&scaler&&PCA/` directory:
   - scaler.pkl
   - pca.pkl
   - Multi_classification_XGBoost_depth_6.pkl

## Usage

1. Start the system:
   ```bash
   python main.py
   ```

2. Access the web interface at `http://localhost:5000`

## Directory Structure

- `~/Desktop/PFA - IDS+ML/pcap_captures/` - PCAP files from tcpdump
- `~/Desktop/PFA - IDS+ML/snort_alerts/` - Snort alert JSON files
- `~/Desktop/PFA - IDS+ML/flow_features/` - Flow features CSV files
- `~/Desktop/PFA - IDS+ML/results/` - ML prediction results
- `Models&&scaler&&PCA/` - ML model files

## Feature Extraction

The system extracts the following features from network traffic:
- Destination Port
- Flow Duration
- Total Fwd/Backward Packets
- Packet Length Statistics
- Flow IAT (Inter-Arrival Time) Statistics
- Flag Counts
- And more (see main.py for complete list)

## Logging

All system activities are logged to `pipeline.log`

## License

MIT License 
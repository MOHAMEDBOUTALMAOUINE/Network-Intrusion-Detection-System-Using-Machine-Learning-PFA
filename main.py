#!/usr/bin/env python3
import os
import time
import logging
import signal
import sys
from datetime import datetime
from pathlib import Path
import subprocess
import json
import pandas as pd
import joblib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from flask import Flask, render_template_string, jsonify
import threading
import numpy as np
import warnings
import shutil
from scapy.all import rdpcap
from pyflowmeter.flow import Flow
from pyflowmeter.features.context.packet_direction import PacketDirection

# Suppress XGBoost warning about serialization
warnings.filterwarnings('ignore', category=UserWarning, module='pickle')

# Configuration - Utilisation du répertoire courant
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
# Ensure paths are properly quoted to handle spaces
PCAP_DIR = os.path.join(CURRENT_DIR, "pcap_captures")
ALERTS_DIR = os.path.join(CURRENT_DIR, "snort_alerts")
SUSPICIOUS_PCAP_DIR = os.path.join(CURRENT_DIR, "suspicious_pcaps")
FEATURES_DIR = os.path.join(CURRENT_DIR, "flow_features")
RESULTS_DIR = os.path.join(CURRENT_DIR, "results")
MODELS_DIR = os.path.join(CURRENT_DIR, "Models&&scaler&&PCA")
PYFLOWMETER_PATH = os.path.join(CURRENT_DIR, "pyflowmeter/tests/test_kali.py")

# Required features for ML model
REQUIRED_FEATURES = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets',
    'Total Backward Packets', 'Total Length of Fwd Packets',
    'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Fwd Packet Length Std', 'Bwd Packet Length Max',
    'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
    'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
    'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Fwd URG Flags',
    'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s',
    'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
    'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
    'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
    'Avg Bwd Segment Size', 'Fwd Header Length.1', 'Subflow Fwd Packets',
    'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
    'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max',
    'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

# Ensure all directories exist
for directory in [PCAP_DIR, ALERTS_DIR, SUSPICIOUS_PCAP_DIR, FEATURES_DIR, RESULTS_DIR]:
    Path(directory).mkdir(parents=True, exist_ok=True)

# Setup logging
logging.basicConfig(
    filename=os.path.join(CURRENT_DIR, 'pipeline.log'),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def check_sudo():
    if os.geteuid() != 0:
        logging.error("This script must be run with sudo privileges")
        print("This script must be run with sudo privileges")
        sys.exit(1)

# Load ML models
try:
    scaler = joblib.load(os.path.join(MODELS_DIR, 'scaler.joblib'))
    pca = joblib.load(os.path.join(MODELS_DIR, 'pca_model.joblib'))
    model = joblib.load(os.path.join(MODELS_DIR, 'Multi_classification_XGBoost_depth_6.joblib'))
    logging.info("ML models loaded successfully")
except Exception as e:
    logging.error(f"Error loading ML models: {e}")
    print(f"Error loading ML models: {e}")
    print(f"Models directory: {MODELS_DIR}")
    print(f"Available files in models directory: {os.listdir(MODELS_DIR) if os.path.exists(MODELS_DIR) else 'Directory does not exist'}")
    sys.exit(1)

def run_tcpdump():
    """Étape 1: Capture du trafic avec tcpdump toutes les 30 secondes"""
    while True:
        try:
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            output_file = os.path.join(PCAP_DIR, f"capture-{timestamp}.pcap")
            
            cmd = [
                "tcpdump",
                "-i", "eth0",
                "-w", output_file,
                "-G", "10",  # Rotation toutes les 30 secondes
                "-W", "1"    # Ne garde qu'un seul fichier à la fois
            ]
            
            subprocess.run(cmd, check=True)
            # Après que tcpdump a fini d'écrire le fichier, on peut l'analyser
            if os.path.exists(output_file):
                logging.info(f"PCAP file complete: {output_file}")
                analyze_with_snort(output_file)
        except Exception as e:
            logging.error(f"Error in tcpdump: {e}")
            time.sleep(5)

def analyze_with_cicflowmeter(pcap_file):
    """Analyse un fichier PCAP avec CICFlowMeter pour extraire les features"""
    try:
        timestamp = os.path.basename(pcap_file).split('-')[1].split('.')[0]
        output_dir = os.path.join(FEATURES_DIR, f"features-{timestamp}")
        
        logging.info(f"Analyzing PCAP with CICFlowMeter: {pcap_file}")
        print(f"Analyzing PCAP with CICFlowMeter: {pcap_file}")
        
        if not os.path.exists(pcap_file):
            logging.error(f"Error: File {pcap_file} not found")
            print(f"Error: File {pcap_file} not found")
            return None

        # Créer le dossier de sortie
        os.makedirs(output_dir, exist_ok=True)

        # Commande pour exécuter CICFlowMeter
        cmd = [
            "sudo",
            "java",
            "-cp", f"{os.path.join(CURRENT_DIR, 'cici/target/SimpleFlowMeterV4-0.0.4-SNAPSHOT.jar')}:{os.path.join(CURRENT_DIR, 'cici/target/lib/*')}",
            "-Djava.library.path=" + os.path.join(CURRENT_DIR, "cici/jnetpcap/linux/jnetpcap-1.4.r1425"),
            "cic.cs.unb.ca.ifm.Cmd",
            pcap_file,
            output_dir
        ]

        # Exécuter CICFlowMeter
        process = subprocess.run(cmd, capture_output=True, text=True)
        
        if process.returncode != 0:
            logging.error(f"CICFlowMeter error: {process.stderr}")
            print(f"CICFlowMeter error: {process.stderr}")
            return None

        # Attendre que le fichier CSV soit généré
        time.sleep(2)  # Attendre un peu pour s'assurer que le fichier est écrit

        # Chercher le fichier CSV généré
        csv_files = [f for f in os.listdir(output_dir) if f.endswith('.csv')]
        if not csv_files:
            logging.error("No CSV file generated by CICFlowMeter")
            print("No CSV file generated by CICFlowMeter")
            return None

        # Lire le fichier CSV généré
        csv_file = os.path.join(output_dir, csv_files[0])
        df = pd.read_csv(csv_file)

        # Sauvegarder le fichier CSV avec les features requises
        output_csv = os.path.join(FEATURES_DIR, f"features-{timestamp}.csv")
        df.to_csv(output_csv, index=False)
        
        logging.info(f"Features extracted and saved to: {output_csv}")
        print(f"Features extracted and saved to: {output_csv}")
        
        return output_csv

    except Exception as e:
        logging.error(f"Error in CICFlowMeter analysis: {e}")
        print(f"Error in CICFlowMeter analysis: {e}")
        return None

def analyze_with_snort(pcap_file):
    """Étape 2: Analyse avec Snort et extraction des paquets suspects"""
    try:
        timestamp = os.path.basename(pcap_file).split('-')[1].split('.')[0]
        alert_file = os.path.join(ALERTS_DIR, f"alert-{timestamp}.json")
        suspicious_pcap = os.path.join(SUSPICIOUS_PCAP_DIR, f"suspicious-{timestamp}.pcap")

        logging.info(f"Analyzing PCAP file: {pcap_file}")
        print(f"Analyzing PCAP file: {pcap_file}")

        # Analyse avec Snort avec les bons paramètres
        snort_cmd = [
            "snort",
            "-c", "/etc/snort/snort.lua",
            "-R", "/etc/snort/rules/local.rules",
            "-r", pcap_file,
            "-A", "alert_json",
            "-l", ALERTS_DIR,
            "-s", "65535",
            "-k", "none"
        ]
        
        logging.info(f"Running Snort command: {' '.join(snort_cmd)}")
        print(f"Running Snort command: {' '.join(snort_cmd)}")
        result = subprocess.run(snort_cmd, check=True, capture_output=True, text=True)
        logging.info(f"Snort output: {result.stdout}")
        if result.stderr:
            logging.warning(f"Snort warnings: {result.stderr}")
        
        # Si des alertes sont générées, extraire les paquets suspects
        alert_path = os.path.join(ALERTS_DIR, "alert_json.txt")
        if os.path.exists(alert_path):
            logging.info(f"Alert file found at: {alert_path}")
            print(f"Alert file found at: {alert_path}")
            
            # Lire le contenu du fichier pour vérifier s'il contient des alertes
            with open(alert_path, 'r') as f:
                content = f.read().strip()
                logging.info(f"Alert file content: {content}")
                print(f"Alert file content: {content}")
                
                # Vérifier si le fichier contient des alertes valides
                if content and content != "[]" and content != "{}":
                    # Renommer le fichier avec le timestamp
                    os.rename(alert_path, alert_file)
                    # Changer les permissions
                    os.chmod(alert_file, 0o644)
                    logging.info(f"Alert file with valid alerts saved as: {alert_file}")
                    print(f"Alert file with valid alerts saved as: {alert_file}")
                    
                    try:
                        # Lire le fichier d'alerte ligne par ligne
                        alerts = []
                        with open(alert_file, 'r') as f:
                            for line in f:
                                line = line.strip()
                                if line:  # Ignorer les lignes vides
                                    try:
                                        alert = json.loads(line)
                                        alerts.append(alert)
                                    except json.JSONDecodeError as e:
                                        logging.warning(f"Error parsing alert line: {e}")
                                        continue
                        
                        # Construire le filtre tcpdump basé sur les IPs des alertes
                        tcpdump_pairs = set()
                        for alert in alerts:
                            if 'src_ap' in alert and 'dst_ap' in alert:
                                src_ip = alert['src_ap'].split(':')[0]
                                dst_ip = alert['dst_ap'].split(':')[0]
                                # Utiliser un tuple trié pour éviter les doublons dans les deux sens
                                pair = tuple(sorted([src_ip, dst_ip]))
                                tcpdump_pairs.add(pair)

                        tcpdump_filter = [f"(host {pair[0]} and host {pair[1]})" for pair in tcpdump_pairs]

                        if tcpdump_filter:
                            # Combiner les filtres avec OR
                            final_filter = " or ".join(tcpdump_filter)
                            
                            # Extraire les paquets suspects avec tcpdump
                            extract_cmd = [
                                "tcpdump",
                                "-r", pcap_file,
                                "-w", suspicious_pcap,
                                final_filter
                            ]
                            
                            logging.info(f"Running tcpdump filter: {' '.join(extract_cmd)}")
                            print(f"Running tcpdump filter: {' '.join(extract_cmd)}")
                            
                            extract_result = subprocess.run(extract_cmd, capture_output=True, text=True)
                            if extract_result.returncode == 0:
                                logging.info(f"Successfully extracted suspicious packets to: {suspicious_pcap}")
                                print(f"Successfully extracted suspicious packets to: {suspicious_pcap}")
                                
                                # Analyser le PCAP suspect avec PyFlowMeter
                                if os.path.exists(suspicious_pcap):
                                    features_file = analyze_with_cicflowmeter(suspicious_pcap)
                                    if features_file:
                                        return suspicious_pcap, True, features_file
                            else:
                                logging.error(f"Error extracting suspicious packets: {extract_result.stderr}")
                                print(f"Error extracting suspicious packets: {extract_result.stderr}")
                        else:
                            logging.warning("No valid IP pairs found in alerts")
                            print("No valid IP pairs found in alerts")
                    
                    except Exception as e:
                        logging.error(f"Error processing alerts: {e}")
                        print(f"Error processing alerts: {e}")
                    
                    return suspicious_pcap, True, None
                else:
                    # Supprimer le fichier s'il ne contient pas d'alertes valides
                    os.remove(alert_path)
                    logging.info("Alert file deleted as it contained no valid alerts")
                    print("Alert file deleted as it contained no valid alerts")
        else:
            logging.info("No alert file generated by Snort")
            print("No alert file generated by Snort")
                    
        return None, False, None
    except Exception as e:
        logging.error(f"Error in Snort analysis: {e}")
        print(f"Error in Snort analysis: {e}")
        return None, False, None

def extract_features(pcap_file):
    """Étape 4: Extraction des features avec PyFlowMeter"""
    try:
        timestamp = os.path.basename(pcap_file).split('-')[1].split('.')[0]
        features_file = os.path.join(FEATURES_DIR, f"features-{timestamp}.csv")
        
        # Use absolute paths and proper quoting
        pcap_file = os.path.abspath(pcap_file)
        features_file = os.path.abspath(features_file)
        
        # Properly handle the virtual environment activation
        venv_activate = os.path.join(CURRENT_DIR, 'pyflowmeter/pyflowmeter_env/bin/activate')
        cmd = f'''
        source "{venv_activate}" && \
        python3 "{PYFLOWMETER_PATH}" -f "{pcap_file}" -o "{features_file}"
        '''
        
        # Use shell=True with proper quoting
        subprocess.run(cmd, shell=True, check=True, executable='/bin/bash')
        return features_file if os.path.exists(features_file) else None
    except Exception as e:
        logging.error(f"Error in feature extraction: {e}")
        return None

def preprocess_and_predict(features_file):
    """Étapes 5-7: Prétraitement, application du modèle et prédiction"""
    temp_file = None
    try:
        # Vérifier si le fichier existe et n'est pas vide
        if not os.path.exists(features_file):
            logging.error(f"Features file not found: {features_file}")
            return None
            
        if os.path.getsize(features_file) == 0:
            logging.error(f"Features file is empty: {features_file}")
            return None
            
        # Lecture du fichier CSV avec gestion des en-têtes sur plusieurs lignes
        try:
            # Lire le fichier en mode texte
            with open(features_file, 'r') as f:
                content = f.read()
            
            # Nettoyer le contenu
            lines = content.split('\n')
            # Trouver la première ligne qui contient des données (contient des chiffres)
            data_start = 0
            for i, line in enumerate(lines):
                if any(c.isdigit() for c in line):
                    data_start = i
                    break
            
            # Extraire les en-têtes et les données
            header_lines = lines[:data_start]
            data_lines = lines[data_start:]
            
            # Nettoyer les en-têtes
            header = ' '.join(header_lines)
            header = ' '.join(header.split())  # Supprimer les espaces multiples
            headers = [h.strip() for h in header.split(',')]
            
            # Créer un fichier temporaire propre
            temp_file = features_file + '.temp'
            with open(temp_file, 'w') as f:
                # Écrire les en-têtes nettoyés
                f.write(','.join(headers) + '\n')
                # Écrire les données
                f.write('\n'.join(data_lines))
            
            # Lire le fichier temporaire avec pandas en chunks
            chunk_size = 10000  # Ajuster selon la mémoire disponible
            df_chunks = []
            for chunk in pd.read_csv(temp_file, chunksize=chunk_size, low_memory=False):
                # Sélectionner uniquement les colonnes requises
                chunk = chunk[REQUIRED_FEATURES]
                # Convertir les colonnes en type float
                for col in chunk.columns:
                    chunk[col] = pd.to_numeric(chunk[col], errors='coerce')
                # Remplacer les valeurs NaN par 0
                chunk = chunk.fillna(0)
                df_chunks.append(chunk)
            
            # Combiner les chunks
            df = pd.concat(df_chunks, ignore_index=True)
            
            # Dédupliquer sur les colonnes 'Src IP', 'Src Port', 'Dst IP'
            dedup_columns = ['Src IP', 'Src Port', 'Dst IP']
            if all(col in df.columns for col in dedup_columns):
                df = df.drop_duplicates(subset=dedup_columns)
            
            # Vérifier si le DataFrame est vide
            if df.empty:
                logging.error(f"No data found in features file: {features_file}")
                return None
            
            # Application du scaler par chunks
            X_chunks = []
            for chunk in np.array_split(df, max(1, len(df) // 10000)):
                try:
                    X_chunk = scaler.transform(chunk)
                    if pca:
                        X_chunk = pca.transform(X_chunk)
                    X_chunks.append(X_chunk)
                except Exception as e:
                    logging.error(f"Error during transformation of chunk: {e}")
                    continue
            
            if not X_chunks:
                logging.error("No valid chunks after transformation")
                return None
            
            X = np.vstack(X_chunks)
            
            # Prédiction
            try:
                predictions = model.predict(X)
                df['prediction'] = predictions
            except Exception as e:
                logging.error(f"Error during prediction: {e}")
                return None
            
            # Sauvegarde des résultats
            timestamp = os.path.basename(features_file).split('-')[1].split('.')[0]
            results_file = os.path.join(RESULTS_DIR, f"results-{timestamp}.csv")
            df.to_csv(results_file, index=False)
            
            logging.info(f"Processing complete. Results saved to {results_file}")
            return results_file
            
        except Exception as e:
            logging.error(f"Error reading CSV file: {e}")
            return None
            
    except Exception as e:
        logging.error(f"Error in preprocessing and prediction: {e}")
        return None
    finally:
        # Nettoyage du fichier temporaire
        if temp_file and os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except Exception as e:
                logging.warning(f"Error removing temporary file: {e}")

class PCAPHandler(FileSystemEventHandler):
    def on_created(self, event):
        # On ne fait plus l'analyse ici, elle est gérée par run_tcpdump
        if event.is_directory or not event.src_path.endswith('.pcap'):
            return
        logging.info(f"New PCAP file created: {event.src_path}")
        print(f"New PCAP file created: {event.src_path}")

# Flask app pour l'interface web
app = Flask(__name__)

@app.route('/')
def index():
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Traffic Analysis</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                .dashboard {
                    padding: 20px;
                }
                .stats-card {
                    background-color: #f8f9fa;
                    border-radius: 10px;
                    padding: 15px;
                    margin-bottom: 20px;
                }
            </style>
            <script>
                function refreshData() {
                    fetch('/results')
                        .then(response => response.json())
                        .then(data => {
                            document.getElementById('resultsTable').innerHTML = data.table;
                            updateCharts(data.stats);
                        });
                }
                
                function updateCharts(stats) {
                    // Mise à jour des graphiques
                    if (window.predictionChart) {
                        window.predictionChart.destroy();
                    }
                    
                    const ctx = document.getElementById('predictionChart').getContext('2d');
                    window.predictionChart = new Chart(ctx, {
                        type: 'pie',
                        data: {
                            labels: Object.keys(stats.prediction_counts),
                            datasets: [{
                                data: Object.values(stats.prediction_counts),
                                backgroundColor: [
                                    '#28a745',
                                    '#dc3545',
                                    '#ffc107',
                                    '#17a2b8'
                                ]
                            }]
                        }
                    });
                }
                
                setInterval(refreshData, 10000);
                window.onload = refreshData;
            </script>
        </head>
        <body>
            <div class="dashboard">
                <h1 class="mb-4">Network Traffic Analysis Dashboard</h1>
                
                <div class="row">
                    <div class="col-md-8">
                        <div class="stats-card">
                            <h3>Recent Traffic Analysis</h3>
                            <div id="resultsTable"></div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="stats-card">
                            <h3>Attack Distribution</h3>
                            <canvas id="predictionChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </body>
        </html>
    ''')

@app.route('/results')
def get_results():
    results = []
    prediction_counts = {}
    
    # Lecture des résultats
    for file in sorted(os.listdir(RESULTS_DIR), reverse=True)[:10]:  # Limité aux 10 derniers fichiers
        if file.startswith('results-') and file.endswith('.csv'):
            df = pd.read_csv(os.path.join(RESULTS_DIR, file))
            results.extend(df.to_dict('records'))
            
            # Comptage des prédictions
            counts = df['prediction'].value_counts().to_dict()
            for k, v in counts.items():
                prediction_counts[k] = prediction_counts.get(k, 0) + v
    
    # Génération du tableau HTML
    table_html = '''
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Prediction</th>
                    <th>Confidence</th>
                </tr>
            </thead>
            <tbody>
                {% for result in results %}
                <tr>
                    <td>{{ result.timestamp }}</td>
                    <td>{{ result.src_ip }}</td>
                    <td>{{ result.dst_ip }}</td>
                    <td>
                        <span class="badge {% if result.prediction == 'Normal' %}bg-success
                        {% elif result.prediction == 'Attack' %}bg-danger
                        {% else %}bg-warning{% endif %}">
                            {{ result.prediction }}
                        </span>
                    </td>
                    <td>{{ "%.2f"|format(result.confidence) if result.confidence else "N/A" }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    '''
    
    return jsonify({
        'table': render_template_string(table_html, results=results),
        'stats': {
            'prediction_counts': prediction_counts
        }
    })

def run_flask():
    app.run(host='127.0.0.1', port=3000)

def signal_handler(sig, frame):
    logging.info("Shutting down...")
    sys.exit(0)

if __name__ == "__main__":
    # Vérification des privilèges sudo
    check_sudo()
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Création des dossiers nécessaires
    for directory in [PCAP_DIR, ALERTS_DIR, SUSPICIOUS_PCAP_DIR, FEATURES_DIR, RESULTS_DIR]:
        Path(directory).mkdir(parents=True, exist_ok=True)
        logging.info(f"Directory {directory} created or verified")
    
    # Démarrage de Flask dans un thread séparé
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()
    
    # Démarrage de tcpdump dans un thread séparé
    tcpdump_thread = threading.Thread(target=run_tcpdump)
    tcpdump_thread.daemon = True
    tcpdump_thread.start()
    
    # Démarrage de l'observateur de fichiers (juste pour le logging)
    event_handler = PCAPHandler()
    observer = Observer()
    observer.schedule(event_handler, PCAP_DIR, recursive=False)
    observer.start()
    logging.info(f"Started watching directory: {PCAP_DIR}")
    print(f"Started watching directory: {PCAP_DIR}")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        logging.info("Stopping observer...")
    observer.join()

CLASS_MAPPING = {
    0: {'name': 'BENIGN', 'description': 'Trafic normal'},
    1: {'name': 'Bot', 'description': 'Trafic de botnet'},
    2: {'name': 'Brute Force', 'description': 'Tentative de force brute'},
    3: {'name': 'DDoS', 'description': 'Attaque par déni de service distribué'},
    4: {'name': 'DoS', 'description': 'Attaque par déni de service'},
    5: {'name': 'Port Scan', 'description': 'Scan de ports'},
    6: {'name': 'Web Attack', 'description': 'Attaque web'}
} 
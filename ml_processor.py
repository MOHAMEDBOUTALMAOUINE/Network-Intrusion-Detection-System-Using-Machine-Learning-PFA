#!/usr/bin/env python3
import os
import sys
import logging
import pandas as pd
import joblib
import numpy as np
from flask import Flask, render_template, request, redirect, url_for, jsonify, render_template_string, send_file, send_from_directory
import threading
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import json
import socket
from contextlib import closing
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor
import queue
import shutil
from pathlib import Path

# Configuration du logging avec rotation des fichiers
from logging.handlers import RotatingFileHandler

# Configuration des chemins
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
FEATURES_DIR = os.path.join(CURRENT_DIR, "flow_features")
RESULTS_DIR = os.path.join(CURRENT_DIR, "flow_results")
MODELS_DIR = os.path.join(CURRENT_DIR, "Models&&scaler&&PCA")
BACKUP_DIR = os.path.join(CURRENT_DIR, "backups")
TEMP_DIR = os.path.join(CURRENT_DIR, "temp")

# Création des répertoires s'ils n'existent pas
for directory in [FEATURES_DIR, RESULTS_DIR, BACKUP_DIR, TEMP_DIR]:
    Path(directory).mkdir(parents=True, exist_ok=True)

# Configuration du logging avec rotation
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler('ml_processing.log', maxBytes=10*1024*1024, backupCount=5),
        logging.StreamHandler()
    ]
)

# Configuration des constantes
MAX_WORKERS = 4
CHUNK_SIZE = 10000
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
ALLOWED_EXTENSIONS = {'.csv', '.pcap', '.pcapng'}

# Mapping des classes avec descriptions
CLASS_MAPPING = {
    0: {'name': 'BENIGN', 'description': 'Trafic normal'},
    1: {'name': 'Bot', 'description': 'Trafic de botnet'},
    2: {'name': 'Brute Force', 'description': 'Tentative de force brute'},
    3: {'name': 'DDoS', 'description': 'Attaque par déni de service distribué'},
    4: {'name': 'DoS', 'description': 'Attaque par déni de service'},
    5: {'name': 'Port Scan', 'description': 'Scan de ports'},
    6: {'name': 'Web Attack', 'description': 'Attaque web'}
}

# Couleurs et icônes pour chaque classe
CLASS_STYLES = {
    'BENIGN': {'color': '#28a745', 'icon': 'shield-check'},
    'Bot': {'color': '#dc3545', 'icon': 'robot'},
    'Brute Force': {'color': '#ffc107', 'icon': 'hammer'},
    'DDoS': {'color': '#fd7e14', 'icon': 'network-wired'},
    'DoS': {'color': '#e83e8c', 'icon': 'bolt'},
    'Port Scan': {'color': '#17a2b8', 'icon': 'search'},
    'Web Attack': {'color': '#6f42c1', 'icon': 'globe'}
}

# Mapping des colonnes du CSV vers les noms attendus par le modèle
COLUMN_MAPPING = {
    'Dst Port': 'Destination Port',
    'Flow Duration': 'Flow Duration',
    'Tot Fwd Pkts': 'Total Fwd Packets',
    'Tot Bwd Pkts': 'Total Backward Packets',
    'TotLen Fwd Pkts': 'Total Length of Fwd Packets',
    'TotLen Bwd Pkts': 'Total Length of Bwd Packets',
    'Fwd Pkt Len Max': 'Fwd Packet Length Max',
    'Fwd Pkt Len Min': 'Fwd Packet Length Min',
    'Fwd Pkt Len Mean': 'Fwd Packet Length Mean',
    'Fwd Pkt Len Std': 'Fwd Packet Length Std',
    'Bwd Pkt Len Max': 'Bwd Packet Length Max',
    'Bwd Pkt Len Min': 'Bwd Packet Length Min',
    'Bwd Pkt Len Mean': 'Bwd Packet Length Mean',
    'Bwd Pkt Len Std': 'Bwd Packet Length Std',
    'Flow Byts/s': 'Flow Bytes/s',
    'Flow Pkts/s': 'Flow Packets/s',
    'Flow IAT Mean': 'Flow IAT Mean',
    'Flow IAT Std': 'Flow IAT Std',
    'Flow IAT Max': 'Flow IAT Max',
    'Flow IAT Min': 'Flow IAT Min',
    'Fwd IAT Tot': 'Fwd IAT Total',
    'Fwd IAT Mean': 'Fwd IAT Mean',
    'Fwd IAT Std': 'Fwd IAT Std',
    'Fwd IAT Max': 'Fwd IAT Max',
    'Fwd IAT Min': 'Fwd IAT Min',
    'Bwd IAT Tot': 'Bwd IAT Total',
    'Bwd IAT Mean': 'Bwd IAT Mean',
    'Bwd IAT Std': 'Bwd IAT Std',
    'Bwd IAT Max': 'Bwd IAT Max',
    'Bwd IAT Min': 'Bwd IAT Min',
    'Fwd PSH Flags': 'Fwd PSH Flags',
    'Fwd URG Flags': 'Fwd URG Flags',
    'Fwd Header Len': 'Fwd Header Length',
    'Bwd Header Len': 'Bwd Header Length',
    'Fwd Pkts/s': 'Fwd Packets/s',
    'Bwd Pkts/s': 'Bwd Packets/s',
    'Pkt Len Min': 'Min Packet Length',
    'Pkt Len Max': 'Max Packet Length',
    'Pkt Len Mean': 'Packet Length Mean',
    'Pkt Len Std': 'Packet Length Std',
    'Pkt Len Var': 'Packet Length Variance',
    'FIN Flag Cnt': 'FIN Flag Count',
    'SYN Flag Cnt': 'SYN Flag Count',
    'RST Flag Cnt': 'RST Flag Count',
    'PSH Flag Cnt': 'PSH Flag Count',
    'ACK Flag Cnt': 'ACK Flag Count',
    'URG Flag Cnt': 'URG Flag Count',
    'CWE Flag Count': 'CWE Flag Count',
    'ECE Flag Cnt': 'ECE Flag Count',
    'Down/Up Ratio': 'Down/Up Ratio',
    'Pkt Size Avg': 'Average Packet Size',
    'Fwd Seg Size Avg': 'Avg Fwd Segment Size',
    'Bwd Seg Size Avg': 'Avg Bwd Segment Size',
    'Subflow Fwd Pkts': 'Subflow Fwd Packets',
    'Subflow Fwd Byts': 'Subflow Fwd Bytes',
    'Subflow Bwd Pkts': 'Subflow Bwd Packets',
    'Subflow Bwd Byts': 'Subflow Bwd Bytes',
    'Init Fwd Win Byts': 'Init_Win_bytes_forward',
    'Init Bwd Win Byts': 'Init_Win_bytes_backward',
    'Fwd Act Data Pkts': 'act_data_pkt_fwd',
    'Fwd Seg Size Min': 'min_seg_size_forward',
    'Active Mean': 'Active Mean',
    'Active Std': 'Active Std',
    'Active Max': 'Active Max',
    'Active Min': 'Active Min',
    'Idle Mean': 'Idle Mean',
    'Idle Std': 'Idle Std',
    'Idle Max': 'Idle Max',
    'Idle Min': 'Idle Min'
}

# Features requises pour le modèle ML
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

class FileManager:
    @staticmethod
    def calculate_file_hash(file_path):
        """Calcule le hash SHA-256 d'un fichier"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    @staticmethod
    def backup_file(file_path):
        """Crée une sauvegarde du fichier"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        backup_path = os.path.join(BACKUP_DIR, f"{os.path.basename(file_path)}.{timestamp}")
        shutil.copy2(file_path, backup_path)
        return backup_path

    @staticmethod
    def cleanup_old_files(directory, max_age_days=7):
        """Nettoie les anciens fichiers"""
        current_time = time.time()
        for filename in os.listdir(directory):
            filepath = os.path.join(directory, filename)
            if os.path.isfile(filepath):
                file_age = current_time - os.path.getmtime(filepath)
                if file_age > (max_age_days * 86400):  # 86400 secondes = 1 jour
                    try:
                        os.remove(filepath)
                        logging.info(f"Fichier supprimé: {filepath}")
                    except Exception as e:
                        logging.error(f"Erreur lors de la suppression de {filepath}: {e}")

class MLProcessor:
    def __init__(self):
        """Initialise le processeur ML avec les modèles"""
        try:
            self.scaler = joblib.load(os.path.join(MODELS_DIR, 'scaler.joblib'))
            self.pca = joblib.load(os.path.join(MODELS_DIR, 'pca_model.joblib'))
            
            # Chargement du modèle XGBoost avec gestion de l'avertissement
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                self.model = joblib.load(os.path.join(MODELS_DIR, 'Multi_classification_XGBoost_depth_6.joblib'))
            
            self.executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
            self.processing_queue = queue.Queue()
            logging.info("Modèles ML chargés avec succès")
        except Exception as e:
            logging.error(f"Erreur lors du chargement des modèles ML: {e}")
            raise

    def process_chunk(self, chunk):
        """Traite un chunk de données"""
        try:
            # Conversion en numérique
            for col in chunk.columns:
                chunk.loc[:, col] = pd.to_numeric(chunk[col], errors='coerce')
            
            # Remplissage des valeurs manquantes
            chunk = chunk.fillna(0)
            
            # Remplacer les valeurs infinies
            chunk = chunk.replace([np.inf, -np.inf], np.finfo(np.float64).max)
            
            # Vérifier et corriger les valeurs trop grandes
            for column in chunk.select_dtypes(include=[np.float64]).columns:
                max_value = np.finfo(np.float64).max
                chunk[column] = chunk[column].clip(-max_value, max_value)
            
            # Application du scaler et PCA
            X_scaled = self.scaler.transform(chunk)
            if self.pca:
                X_processed = self.pca.transform(X_scaled)
            else:
                X_processed = X_scaled
            
            # Prédiction
            predictions = self.model.predict(X_processed)
            probabilities = self.model.predict_proba(X_processed)
            
            return predictions, probabilities
        except Exception as e:
            logging.error(f"Erreur lors du traitement du chunk: {e}")
            return None, None

    def process_features(self, features_file):
        """Traite les features et fait les prédictions"""
        try:
            # Vérification du fichier
            if not self.is_file_valid(features_file):
                return None

            # Création d'une sauvegarde
            backup_path = FileManager.backup_file(features_file)
            logging.info(f"Sauvegarde créée: {backup_path}")

            # Lecture du fichier en chunks
            chunks = []
            predictions_list = []
            probabilities_list = []
            ip_data = []  # Pour stocker les données IP

            # Lire le premier chunk pour vérifier les colonnes
            first_chunk = pd.read_csv(features_file, nrows=1)
            logging.info(f"Colonnes disponibles dans le fichier: {first_chunk.columns.tolist()}")

            for chunk in pd.read_csv(features_file, chunksize=CHUNK_SIZE):
                # Sauvegarde des données IP avant le traitement
                ip_columns = ['Src IP', 'Dst IP', 'Source IP', 'Destination IP', 'src_ip', 'dst_ip', 'source_ip', 'destination_ip']
                found_ip_columns = [col for col in ip_columns if col in chunk.columns]
                
                if found_ip_columns:
                    logging.info(f"Colonnes IP trouvées: {found_ip_columns}")
                    # Utiliser les premières colonnes IP trouvées
                    src_col = found_ip_columns[0]
                    dst_col = found_ip_columns[1] if len(found_ip_columns) > 1 else None
                    
                    ip_df = pd.DataFrame({
                        'Source IP': chunk[src_col],
                        'Destination IP': chunk[dst_col] if dst_col else ['Unknown'] * len(chunk)
                    })
                    ip_data.append(ip_df)
                else:
                    logging.warning("Aucune colonne IP trouvée, utilisation des valeurs par défaut")
                    default_ips = pd.DataFrame({
                        'Source IP': ['Unknown'] * len(chunk),
                        'Destination IP': ['Unknown'] * len(chunk)
                    })
                    ip_data.append(default_ips)

                # Renommer les colonnes selon le mapping
                chunk = chunk.rename(columns=COLUMN_MAPPING)
                
                # Ajouter la colonne manquante avec des valeurs 0
                chunk['Fwd Header Length.1'] = 0
                
                # Mettre à zéro les colonnes spécifiques
                columns_to_zero = ['Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']
                for col in columns_to_zero:
                    if col in chunk.columns:
                        chunk[col] = 0

                # Vérification des features requises après le mapping
                if not all(feature in chunk.columns for feature in REQUIRED_FEATURES):
                    missing = [f for f in REQUIRED_FEATURES if f not in chunk.columns]
                    logging.error(f"Features manquantes après mapping: {missing}")
                    return None

                # Traitement du chunk
                chunk = chunk[REQUIRED_FEATURES]
                predictions, probabilities = self.process_chunk(chunk)
                
                if predictions is not None:
                    chunks.append(chunk)
                    predictions_list.extend(predictions)
                    probabilities_list.extend(probabilities)

            if not chunks:
                logging.error("Aucun chunk n'a pu être traité")
                return None

            # Combinaison des résultats
            df = pd.concat(chunks, ignore_index=True)
            
            # Gestion des prédictions
            if isinstance(predictions_list[0], str):
                # Si les prédictions sont déjà des chaînes de caractères
                df['prediction'] = predictions_list
            else:
                # Si les prédictions sont des indices numériques
                df['prediction'] = [CLASS_MAPPING.get(p, {'name': 'Unknown'})['name'] for p in predictions_list]
            
            # Correction robuste pour la description
            def get_description(pred):
                if isinstance(pred, (int, np.integer)):
                    return CLASS_MAPPING.get(pred, {'description': 'Unknown'})['description']
                pred_str = str(pred).strip().upper()
                for v in CLASS_MAPPING.values():
                    if v['name'].upper() == pred_str:
                        return v['description']
                return 'Unknown'
            df['description'] = [get_description(p) for p in df['prediction']]
            
            df['confidence'] = np.max(probabilities_list, axis=1)

            # Ajout des données IP
            ip_df = pd.concat(ip_data, ignore_index=True)
            df = pd.concat([ip_df, df], axis=1)

            # Ajout d'un timestamp unique à chaque prédiction pour la timeline
            if 'timestamp' not in df.columns:
                base_time = datetime.now()
                df['timestamp'] = [
                    (base_time + pd.Timedelta(seconds=i)).strftime('%Y-%m-%d %H:%M:%S')
                    for i in range(len(df))
                ]

            # Vérification finale des données
            logging.info(f"Colonnes finales: {df.columns.tolist()}")
            logging.info(f"Premières lignes des données IP: {ip_df.head().to_dict()}")

            # Sauvegarde des résultats
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            results_file = os.path.join(RESULTS_DIR, f"results-{timestamp}.csv")
            df.to_csv(results_file, index=False)

            # Génération du rapport
            report = self.generate_report(df, features_file, results_file)
            report_file = results_file.replace('.csv', '_report.json')
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=4)

            logging.info(f"Traitement terminé. Résultats sauvegardés dans {results_file}")
            return results_file, report_file

        except Exception as e:
            logging.error(f"Erreur lors du traitement des features: {e}")
            return None

    def generate_report(self, df, features_file, results_file):
        """Génère un rapport détaillé des prédictions"""
        prediction_counts = {class_info['name']: int((df['prediction'] == class_info['name']).sum()) 
                           for class_info in CLASS_MAPPING.values()}
        
        return {
            'features_file': features_file,
            'results_file': results_file,
            'total_samples': len(df),
            'predictions': prediction_counts,
            'average_confidence': float(df['confidence'].mean()),
            'timestamp': datetime.now().isoformat(),
            'statistics': {
                'confidence_stats': {
                    'mean': float(df['confidence'].mean()),
                    'std': float(df['confidence'].std()),
                    'min': float(df['confidence'].min()),
                    'max': float(df['confidence'].max())
                },
                'top_predictions': df['prediction'].value_counts().head(3).to_dict()
            }
        }

    def is_file_valid(self, file_path):
        """Vérifie si le fichier est valide"""
        try:
            if not os.path.exists(file_path):
                logging.error(f"Le fichier {file_path} n'existe pas")
                return False

            if os.path.getsize(file_path) == 0:
                logging.error(f"Le fichier {file_path} est vide")
                return False

            if os.path.getsize(file_path) > MAX_FILE_SIZE:
                logging.error(f"Le fichier {file_path} est trop volumineux")
                return False

            extension = os.path.splitext(file_path)[1].lower()
            if extension not in ALLOWED_EXTENSIONS:
                logging.error(f"Extension de fichier non autorisée: {extension}")
                return False

            return True
        except Exception as e:
            logging.error(f"Erreur lors de la vérification du fichier {file_path}: {e}")
            return False

class FeaturesHandler(FileSystemEventHandler):
    def __init__(self, ml_processor):
        self.ml_processor = ml_processor
        self.processed_files = set()
        self.processing_queue = queue.Queue()
        self.worker_thread = threading.Thread(target=self._process_queue, daemon=True)
        self.worker_thread.start()

    def _process_queue(self):
        """Traite les fichiers dans la file d'attente"""
        while True:
            try:
                file_path = self.processing_queue.get()
                if file_path not in self.processed_files:
                    result = self.ml_processor.process_features(file_path)
                    if result:
                        self.processed_files.add(file_path)
                        logging.info(f"Fichier traité avec succès: {file_path}")
                    else:
                        logging.warning(f"Le fichier n'a pas pu être traité: {file_path}")
                self.processing_queue.task_done()
            except Exception as e:
                logging.error(f"Erreur lors du traitement de la file d'attente: {e}")
            time.sleep(1)

    def on_created(self, event):
        if event.is_directory:
            return

        if (event.src_path.endswith('.csv') and 
            'features-' in event.src_path and 
            event.src_path not in self.processed_files):
            
            try:
                time.sleep(1)  # Attente pour s'assurer que le fichier est complètement écrit
                logging.info(f"Nouveau fichier de features détecté: {event.src_path}")
                self.processing_queue.put(event.src_path)
            except Exception as e:
                logging.error(f"Erreur lors de l'ajout du fichier à la file d'attente: {e}")

# Interface Flask améliorée
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('dashboard.html', class_styles=CLASS_STYLES)

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return redirect(url_for('index'))
    file = request.files['file']
    if file.filename == '':
        return redirect(url_for('index'))
    if file and file.filename.endswith('.csv'):
        save_path = os.path.join(FEATURES_DIR, file.filename)
        file.save(save_path)
        # Optionnel : lancer le traitement automatique ici
        return redirect(url_for('index'))
    return redirect(url_for('index'))

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

@app.route('/results')
def get_results():
    results = []
    prediction_counts = {class_info['name']: 0 for class_info in CLASS_MAPPING.values()}
    time_series = {}  # Pour stocker les données temporelles
    
    try:
        # Lecture des résultats
        for file in sorted(os.listdir(RESULTS_DIR), reverse=True)[:10]:
            if file.startswith('results-') and file.endswith('.csv'):
                try:
                    df = pd.read_csv(os.path.join(RESULTS_DIR, file))
                    
                    # Vérifier et ajouter les colonnes IP si manquantes
                    if 'Source IP' not in df.columns:
                        df['Source IP'] = 'Unknown'
                    if 'Destination IP' not in df.columns:
                        df['Destination IP'] = 'Unknown'
                    
                    # S'assurer que toutes les colonnes requises sont présentes
                    required_columns = ['Source IP', 'Destination IP', 'prediction', 'description', 'confidence']
                    for col in required_columns:
                        if col not in df.columns:
                            df[col] = 'Unknown' if col != 'confidence' else 0.0
                    
                    # Filtrer les paquets avec un niveau de confiance > 0.3
                    df = df[df['confidence'] > 0.3]
                    
                    # Convertir en liste de dictionnaires
                    results.extend(df[required_columns].to_dict('records'))
                    
                    # Comptage des prédictions
                    counts = df['prediction'].value_counts().to_dict()
                    for k, v in counts.items():
                        if k in prediction_counts:
                            prediction_counts[k] += v
                    
                    # Génération de la série temporelle
                    if 'timestamp' in df.columns:
                        df['hour'] = pd.to_datetime(df['timestamp']).dt.strftime('%Y-%m-%d %H:00')
                        hourly_counts = df.groupby(['hour', 'prediction']).size().unstack(fill_value=0)
                        for hour, row in hourly_counts.iterrows():
                            if hour not in time_series:
                                time_series[hour] = {}
                            for pred_type, count in row.items():
                                time_series[hour][pred_type] = time_series[hour].get(pred_type, 0) + count
                    
                except Exception as e:
                    logging.error(f"Erreur lors de la lecture du fichier {file}: {e}")
                    continue
    except Exception as e:
        logging.error(f"Erreur lors de la lecture des résultats: {e}")
    
    # Génération du tableau HTML
    table_html = '''
        <table class="table table-hover">
            <thead>
                <tr>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Type d'attaque</th>
                    <th>Description</th>
                    <th>Niveau de confiance</th>
                </tr>
            </thead>
            <tbody>
                {% for result in results %}
                <tr>
                    <td>{{ result['Source IP'] }}</td>
                    <td>{{ result['Destination IP'] }}</td>
                    <td>
                        <span class="attack-badge" style="background-color: {{ class_styles[result.prediction].color }}">
                            <i class="bi bi-{{ class_styles[result.prediction].icon }}"></i>
                            {{ result.prediction }}
                        </span>
                    </td>
                    <td>{{ result.description }}</td>
                    <td>
                        <div class="confidence-bar">
                            <div class="confidence-fill" style="width: {{ (result.confidence * 100)|round }}%"></div>
                        </div>
                        <small>{{ (result.confidence * 100)|round }}%</small>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    '''
    
    # Si pas de résultats, ajouter un message
    if not results:
        table_html = '<div class="alert alert-info">Aucun résultat disponible pour le moment.</div>'
    
    return jsonify({
        'table': render_template_string(table_html, results=results, class_styles=CLASS_STYLES),
        'stats': {
            'prediction_counts': prediction_counts,
            'total_samples': len(results),
            'average_confidence': float(pd.DataFrame(results)['confidence'].mean()) if results else 0
        },
        'time_series': time_series  # Ajout de la série temporelle
    })

def run_flask(port=None):
    app.run(host='127.0.0.1', port=3005, debug=False)

def find_free_port():
    """Trouve un port libre"""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(('', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]

def watch_features_directory():
    """Surveille le répertoire des features pour les nouveaux fichiers"""
    event_handler = FeaturesHandler(MLProcessor())
    observer = Observer()
    observer.schedule(event_handler, FEATURES_DIR, recursive=False)
    observer.start()
    logging.info(f"Started watching directory: {FEATURES_DIR}")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        logging.info("Stopping observer...")
    observer.join()

if __name__ == "__main__":
    # Nettoyage des anciens fichiers
    FileManager.cleanup_old_files(FEATURES_DIR)
    FileManager.cleanup_old_files(RESULTS_DIR)
    FileManager.cleanup_old_files(BACKUP_DIR)
    
    # Démarrage de Flask dans un thread séparé
    flask_thread = threading.Thread(target=run_flask, args=(find_free_port(),))
    flask_thread.daemon = True
    flask_thread.start()
    
    # Démarrage de la surveillance du répertoire
    watch_features_directory() 
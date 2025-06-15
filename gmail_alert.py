#!/usr/bin/env python3
import os
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import pandas as pd
from pathlib import Path
import logging
import time
import sys

# Configuration
GMAIL_USER = "ids.alerts.pfa@gmail.com"
GMAIL_PASSWORD = "mqpz xaox rscv tuwd"
RECIPIENT_EMAIL = "ids.alerts.pfa@gmail.com"
ALERTS_HISTORY_FILE = "alerts_history.json"
THRESHOLD_INCREASE = 1.5  # Seuil d'augmentation pour considérer une alerte comme significative
CHECK_INTERVAL = 30  # Intervalle de vérification en secondes

# Configuration du logging
logging.basicConfig(
    filename='gmail_alerts.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class AlertManager:
    def __init__(self):
        self.alerts_history = self.load_alerts_history()
        self.current_alerts = {}
        self.last_check_time = 0
        self.processed_files = set()

    def load_alerts_history(self):
        """Charge l'historique des alertes depuis le fichier JSON"""
        if os.path.exists(ALERTS_HISTORY_FILE):
            try:
                with open(ALERTS_HISTORY_FILE, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                logging.error("Erreur lors de la lecture du fichier d'historique")
                return {}
        return {}

    def save_alerts_history(self):
        """Sauvegarde l'historique des alertes dans le fichier JSON"""
        with open(ALERTS_HISTORY_FILE, 'w') as f:
            json.dump(self.alerts_history, f, indent=4)

    def check_new_alerts(self, results_dir):
        """Vérifie les nouveaux résultats et identifie les nouvelles alertes"""
        new_alerts = []
        current_time = time.time()
        
        # Parcourir les fichiers de résultats JSON dans flow_results
        for result_file in Path(results_dir).glob("*_report.json"):
            # Vérifier si le fichier a été modifié après la dernière vérification
            file_mtime = os.path.getmtime(result_file)
            if file_mtime <= self.last_check_time or str(result_file) in self.processed_files:
                continue

            try:
                with open(result_file, 'r') as f:
                    results = json.load(f)
                
                # Extraire les prédictions du fichier JSON
                if 'predictions' in results:
                    predictions = results['predictions']
                    for attack_type, count in predictions.items():
                        if attack_type == 'BENIGN':  # Ignorer le trafic normal
                            continue
                            
                        # Mettre à jour les statistiques dans alerts_history
                        if attack_type not in self.alerts_history:
                            self.alerts_history[attack_type] = 0
                        
                        # Si le nombre d'attaques a augmenté
                        if count > 0:
                            previous_count = self.alerts_history[attack_type]
                            self.alerts_history[attack_type] += count
                            
                            # Créer une alerte
                            new_alerts.append({
                                'type': attack_type,
                                'count': count,
                                'previous_count': previous_count,
                                'total_count': self.alerts_history[attack_type],
                                'status': 'new' if previous_count == 0 else 'increased',
                                'timestamp': results.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                            })
                
                # Marquer le fichier comme traité
                self.processed_files.add(str(result_file))
                
            except Exception as e:
                logging.error(f"Erreur lors de la lecture du fichier {result_file}: {e}")

        self.last_check_time = current_time

        if new_alerts:
            self.save_alerts_history()
            return new_alerts
        return []

    def send_alert_email(self, alerts):
        """Envoie un email avec les nouvelles alertes"""
        if not alerts:
            return

        msg = MIMEMultipart()
        msg['From'] = GMAIL_USER
        msg['To'] = RECIPIENT_EMAIL
        msg['Subject'] = f"Alertes IDS - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

        # Création du corps du message
        body = "Nouvelles alertes détectées :\n\n"
        for alert in alerts:
            if alert['status'] == 'new':
                body += f"⚠️ Nouvelle attaque détectée : {alert['type']}\n"
                body += f"Nombre d'occurrences : {alert['count']}\n"
                body += f"Total cumulé : {alert['total_count']}\n"
                body += f"Timestamp : {alert['timestamp']}\n\n"
            else:
                body += f"⚠️ Augmentation de l'attaque : {alert['type']}\n"
                body += f"Nombre d'occurrences précédent : {alert['previous_count']}\n"
                body += f"Nouvelles occurrences : {alert['count']}\n"
                body += f"Total cumulé : {alert['total_count']}\n"
                body += f"Timestamp : {alert['timestamp']}\n\n"

        msg.attach(MIMEText(body, 'plain'))

        try:
            # Connexion au serveur SMTP de Gmail
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(GMAIL_USER, GMAIL_PASSWORD)
            
            # Envoi de l'email
            server.send_message(msg)
            server.quit()
            
            logging.info(f"Email d'alerte envoyé avec succès pour {len(alerts)} alertes")
            print(f"Email d'alerte envoyé avec succès pour {len(alerts)} alertes")
        except Exception as e:
            error_msg = f"Erreur lors de l'envoi de l'email : {e}"
            logging.error(error_msg)
            print(error_msg)
            print("Vérifiez que le mot de passe d'application Gmail est correct et que l'accès SMTP est autorisé.")

def main():
    print("Démarrage du système d'alertes par email...")
    print(f"Vérification toutes les {CHECK_INTERVAL} secondes")
    print("Appuyez sur Ctrl+C pour arrêter")
    
    alert_manager = AlertManager()
    results_dir = "flow_results"
    
    try:
        while True:
            # Vérifier les nouvelles alertes
            new_alerts = alert_manager.check_new_alerts(results_dir)
            
            # Envoyer l'email si des nouvelles alertes sont détectées
            if new_alerts:
                alert_manager.send_alert_email(new_alerts)
            
            # Attendre avant la prochaine vérification
            time.sleep(CHECK_INTERVAL)
            
    except KeyboardInterrupt:
        print("\nArrêt du système d'alertes...")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Erreur inattendue : {e}")
        print(f"Erreur inattendue : {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
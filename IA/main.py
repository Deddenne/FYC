from scapy.all import sniff, IP
from collections import Counter
import joblib
import smtplib
from email.mime.text import MIMEText
import time
from datetime import datetime

# Charger le modèle IA
model = joblib.load("ddos_detector_model.pkl")

# Configuration
MONITORING_DURATION = 10  # Durée de la surveillance en secondes
email_sender = "vmia@example.com"
email_password = "yourpassword"
email_recipient = "admin@example.com"
smtp_server = "smtp.example.com"
smtp_port = 587
html_file = "traffic_report.html"  # Nom du fichier HTML de sortie

# Envoi d'une alerte par e-mail
def send_email(alert_message):
    msg = MIMEText(alert_message)
    msg["Subject"] = "ALERT: Potential Attack Detected"
    msg["From"] = email_sender
    msg["To"] = email_recipient

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(email_sender, email_password)
        server.send_message(msg)
    print("Alert email sent!")

# Détection avec IA
def detect_attack(ip_count, packet_rate):
    prediction = model.predict([[ip_count, packet_rate]])
    return prediction[0]  # 0 = normal, 1 = attaque

# Collecte des données réseau
def monitor_traffic(duration):
    packet_list = []
    start_time = time.time()

    def packet_callback(packet):
        if IP in packet:
            packet_list.append(packet[IP].src)

    sniff(filter="ip", prn=packet_callback, timeout=duration)
    end_time = time.time()

    # Calcul des statistiques
    ip_counter = Counter(packet_list)
    ip_count = len(ip_counter)  # Nombre unique d'IP
    packet_rate = len(packet_list) / (end_time - start_time)  # Taux de paquets par seconde
    return ip_count, packet_rate, ip_counter

# Écriture des résultats dans un fichier HTML
def write_to_html(ip_count, packet_rate, attack_type, ip_counter, current_time):
    attack_status = "Potential Attack Detected" if attack_type == 1 else "Normal"  # Mise à jour pour cohérence
    
    # Si le fichier n'existe pas, ajouter l'en-tête HTML
    try:
        with open(html_file, "r") as file:
            pass
    except FileNotFoundError:
        with open(html_file, "w") as file:
            file.write("<html><head><title>Traffic Monitoring Report</title>")
            file.write("<style>table {width: 100%; border-collapse: collapse;} th, td {padding: 8px; text-align: left; border: 1px solid #ddd;} th {background-color: #f2f2f2;}</style></head><body>")
            file.write("<h1>Network Traffic Monitoring Report</h1>")
            file.write("<table><tr><th>Date & Time</th><th>Unique IPs</th><th>Packet Rate (packets/sec)</th><th>Status</th><th>IP Addresses</th></tr>")
    
    # Ajouter les résultats de la surveillance sous forme de ligne dans le tableau
    ip_list = "<br>".join(ip_counter.keys())  # Afficher les IP uniques détectées
    with open(html_file, "a") as file:
        file.write(f"<tr><td>{current_time}</td><td>{ip_count}</td><td>{packet_rate:.2f}</td><td>{attack_status}</td><td>{ip_list}</td></tr>")
    
    # Pas de fermeture du tableau, elle se fait après la fin de la boucle de surveillance
    # Le tableau sera fermé à la fin de l'exécution du script

# Script principal
def main():
    print("Starting network monitoring with AI...\n")
    while True:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"Monitoring traffic from {current_time} for {MONITORING_DURATION} seconds...")

        # Surveiller et analyser le trafic
        ip_count, packet_rate, ip_counter = monitor_traffic(MONITORING_DURATION)

        # Affichage des résultats dans le terminal
        print("\n--- Monitoring Statistics ---")
        print(f"Unique IPs: {ip_count}")
        print(f"Packet Rate: {packet_rate:.2f} packets/sec")
        print(f"Unique IPs detected: {', '.join(ip_counter.keys())}")
        
        attack_type = detect_attack(ip_count, packet_rate)

        if attack_type == 1:
            alert_message = f"ALERT: Potential attack detected!\n\nStats:\nUnique IPs = {ip_count}\nPacket Rate = {packet_rate:.2f} packets/sec\nTime: {current_time}"
            print(f"\n{alert_message}\n")
            ########################################### send_email(alert_message)
        else:
            print("\nTraffic appears normal.\n")

        # Écriture des résultats dans le fichier HTML
        write_to_html(ip_count, packet_rate, attack_type, ip_counter, current_time)

        # Attente avant la prochaine surveillance
        print("Waiting for the next monitoring cycle...\n")
        time.sleep(5)

if __name__ == "__main__":
    main()

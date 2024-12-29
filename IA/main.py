from scapy.all import sniff, IP
from collections import Counter
import joblib
import smtplib
from email.mime.text import MIMEText
import time

# Charger le modèle IA
model = joblib.load("ddos_detector_model.pkl")

# Configuration
MONITORING_DURATION = 10  # Durée de la surveillance en secondes
email_sender = "vmia@example.com"
email_password = "yourpassword"
email_recipient = "admin@example.com"
smtp_server = "smtp.example.com"
smtp_port = 587

# Envoi d'une alerte par e-mail
def send_email(alert_message):
    msg = MIMEText(alert_message)
    msg["Subject"] = "ALERT: Potential DDoS Attack Detected"
    msg["From"] = email_sender
    msg["To"] = email_recipient

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(email_sender, email_password)
        server.send_message(msg)
    print("Alert email sent!")

# Détection avec IA
def detect_ddos_with_ai(ip_count, packet_rate):
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
    return ip_count, packet_rate

# Script principal
def main():
    print("Starting network monitoring with AI...")
    while True:
        print(f"Monitoring traffic for {MONITORING_DURATION} seconds...")
        ip_count, packet_rate = monitor_traffic(MONITORING_DURATION)

        print(f"Stats: Unique IPs = {ip_count}, Packet Rate = {packet_rate:.2f}")
        is_ddos = detect_ddos_with_ai(ip_count, packet_rate)

        if is_ddos == 1:
            alert_message = f"ALERT: Potential DDoS detected! Unique IPs = {ip_count}, Packet Rate = {packet_rate:.2f}"
            print(alert_message)
            send_email(alert_message)
        else:
            print("Traffic appears normal.")

        time.sleep(5)  # Pause avant la prochaine surveillance

if __name__ == "__main__":
    main()

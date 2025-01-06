from scapy.all import sniff, IP, ARP, Ether, srp
from collections import Counter, defaultdict
import joblib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time
from datetime import datetime
from dotenv import load_dotenv
import os
import subprocess
from scapy.config import conf

# Charger le modèle IA
model = joblib.load("ddos_detector_model.pkl")

# Configuration
MONITORING_DURATION = 10 # Durée de la surveillance en secondes

# Charger les variables d'environnement depuis le fichier .env
load_dotenv()

# Paramètres de connexion
smtp_server = os.getenv("SMTP_SERVER")
smtp_port = os.getenv("SMTP_PORT")
sender_email = os.getenv("EMAIL_SENDER")
receiver_email = os.getenv("EMAIL_RECIPIENT")
password = os.getenv("EMAIL_PASSWORD")

# Génération du fichier HTML de sortie
html_file = "traffic_report.html" 

# Envoi d'une alerte par e-mail avec Outlook
def send_email(alert_message, attacker_ip=None):
    msg = MIMEMultipart()
    msg["Subject"] = "ALERT: Potential Attack Detected"
    msg["From"] = sender_email
    msg["To"] = receiver_email

    # Corps du message
    email_body = alert_message
    if attacker_ip:
        email_body += f"\n\nIP suspecte principale : {attacker_ip}"
    msg.attach(MIMEText(email_body, "plain"))

    # Envoi via le serveur SMTP d'Outlook
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Sécurise la connexion
        server.login(sender_email, password)
        text = msg.as_string()
        server.sendmail(sender_email, receiver_email, text)
        print("E-mail envoyé avec succès !")
    except Exception as e:
        print(f"Une erreur est survenue : {e}")
    finally:
        server.quit()
    print("Alert email sent via Outlook!")

# Détection avec IA
def detect_attack(ip_count, packet_rate):
    prediction = model.predict([[ip_count, packet_rate]])
    return prediction[0]  # 0 = normal, 1 = attaque


# Fonction pour récupérer toutes les IPs d'un sous-réseau spécifique
def get_all_ips(subnet):
    """
    Scanne le réseau sur toutes les interfaces disponibles et récupère toutes les IP connectées dans un sous-réseau.
    """
    all_ips = set()
    
    # Liste toutes les interfaces
    interfaces = conf.ifaces
    
    for iface_name in interfaces.data.keys():
        try:
            # Création d'une requête ARP pour chaque interface
            arp = ARP(pdst=subnet)  # Plage d'IP à scanner
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            result = srp(packet, timeout=2, iface=iface_name, verbose=False)[0]

            # Récupération des IP des réponses
            for _, received in result:
                all_ips.add(received.psrc)
        except Exception as e:
            print(f"Erreur sur l'interface {iface_name}: {e}")
    
    print(f"IP Found: {all_ips}")

    return list(all_ips)


# Collecte des données réseau sur une plage d'IP
# def monitor_traffic(duration, subnet="192.168.100.0/24"):
#     """
#     Surveille le trafic réseau pour une durée donnée et récupère les statistiques pour une plage d'IP spécifique.
#     """
#     packet_list = []
#     start_time = time.time()

#     # Récupérer toutes les IPs de la plage donnée
#     all_ips = get_all_ips(subnet)
#     ip_set = set(all_ips)  # Convertir en set pour vérification rapide

#     print(ip_set)

#     def packet_callback(packet):
#         if IP in packet and packet[IP].src in ip_set:  # Filtrer uniquement les paquets venant des IPs dans la plage
#             packet_list.append(packet[IP].src)

#     sniff(filter="ip", prn=packet_callback, timeout=duration, iface=None)
#     end_time = time.time()

#     # Calcul des statistiques
#     ip_counter = all_ips
#     ip_count = len(all_ips)
#     packet_rate = len(packet_list) / (end_time - start_time)  # Taux de paquets par seconde
    
#     return ip_count, packet_rate, ip_counter

def monitor_traffic(duration, subnet):
    # Récupération des IPs à partir du sous-réseau
    all_ips = get_all_ips(subnet)
    global_traffic_count = 0

    # Compte des paquets pour chaque IP
    for target_ip in all_ips:
        traffic_count = 0  # Compteur de trafic (en octets)
        
        # Fonction pour traiter les paquets
        def process_packet(packet):
            nonlocal traffic_count
            if packet.haslayer("IP"):
                src_ip = packet["IP"].src
                dst_ip = packet["IP"].dst
                packet_size = len(packet)  # Taille du paquet en octets

                # Vérifier si l'IP est source ou destination
                if src_ip == target_ip or dst_ip == target_ip:
                    traffic_count += packet_size

        # Capture des paquets pendant une durée spécifique
        sniff(filter=f"ip host {target_ip}", prn=process_packet, store=False, timeout=duration)

        global_traffic_count += traffic_count  # On incrémente le trafic global

    # Nombre d'IP unique dans la plage
    ip_count = len(all_ips)
    print(f"Unique IPs: {all_ips}")
    
    return ip_count, global_traffic_count, all_ips

# Écriture des résultats dans un fichier HTML
def write_to_html(ip_count, packet_rate, attack_type, ip_counter, current_time):
    attack_status = "Potential Attack Detected" if attack_type == 1 else "Normal"
    
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


# block ip
def add_iptables_rule(block_ip):
    try:
        # Commande iptables pour bloquer une IP
        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", block_ip, "-j", "DROP"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return f"Règle ajoutée avec succès pour bloquer : {block_ip}"
    except subprocess.CalledProcessError as e:
        return f"Erreur lors de l'ajout de la règle : {e.stderr}"



# Script principal
def main():
    print("Starting network monitoring with AI...\n")
    while True:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"Monitoring traffic from {current_time} for {MONITORING_DURATION} seconds...")

        # Surveiller et analyser le trafic
        ip_count, packet_rate, ip_counter = monitor_traffic(MONITORING_DURATION, "192.168.100.0/24")

        # Affichage des résultats dans le terminal
        print("\n--- Monitoring Statistics ---")
        print(f"Unique IPs: {ip_count}")
        print(f"Packet Rate: {packet_rate:.2f} packets/sec")
        print(f"Unique IPs detected: {ip_counter}")

        attack_type = detect_attack(ip_count, packet_rate)

        if attack_type == 1:
            # Identification de l'IP la plus active (potentiellement l'attaquant)
            attacker_ip = ip_counter.most_common(1)[0][0]
            alert_message = f"ALERT: Potential attack detected!\n\nStats:\nUnique IPs = {ip_count}\nPacket Rate = {packet_rate:.2f} packets/sec\nTime: {current_time}"
            print(f"\n{alert_message}\nIP suspecte principale : {attacker_ip}\n")

            # Envoi d'une alerte par email
            add_iptables_rule(attacker_ip)
            send_email(alert_message, attacker_ip)
        else:
            print("\nTraffic appears normal.\n")

        # Écriture des résultats dans le fichier HTML
        write_to_html(ip_count, packet_rate, attack_type, ip_counter, current_time)

        # Attente avant la prochaine surveillance
        print("Waiting for the next monitoring cycle...\n")
        time.sleep(5)

if __name__ == "__main__":
    main()

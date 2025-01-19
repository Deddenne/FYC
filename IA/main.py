from scapy.all import sniff, IP
from collections import Counter
import joblib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time
from datetime import datetime
from dotenv import load_dotenv
import os
import subprocess
from jinja2 import Template

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
def send_email(alert_message, attacker_ip=None, html_file='report.html'):
    # Lire le contenu HTML de report.html
    try:
        with open(html_file, 'r') as file:
            html_content = file.read()
    except FileNotFoundError:
        print(f"Erreur : Le fichier {html_file} n'a pas été trouvé.")
        return

    # Remplacer les placeholders dans le contenu HTML
    html_content = html_content.replace('{alert_message}', alert_message)
    if attacker_ip:
        html_content = html_content.replace('{attacker_ip}', attacker_ip)
    else:
        html_content = html_content.replace('{attacker_ip}', 'N/A')  # Valeur par défaut si aucune IP n'est fournie

    # Préparer le message e-mail
    msg = MIMEMultipart()
    msg["Subject"] = "ALERT: Potential Attack Detected"
    msg["From"] = sender_email
    msg["To"] = receiver_email

    # Corps du message avec HTML
    msg.attach(MIMEText(html_content, "html"))

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

# Collecte des données réseau
def monitor_traffic(duration,interface="ens33"):
    start_time = time.time()
    packets = []
    
    def packet_callback(packet):
        """Callback pour capturer les paquets IP."""
        if packet.haslayer("IP"):
            packets.append(packet["IP"].src)
    
    # Capture les paquets sur l'interface réseau
    sniff(iface=interface, prn=packet_callback, timeout=duration, store=False)
    
    # Calcul des métriques
    elapsed_time = time.time() - start_time
    ip_counter = Counter(packets)
    ip_count = len(ip_counter)  # Nombre d'IPs uniques
    packet_rate = len(packets) / elapsed_time if elapsed_time > 0 else 0  # Taux de paquets par seconde

    return ip_count, packet_rate, ip_counter


# Écriture des résultats dans un fichier HTML
def write_to_html(ip_count, packet_rate, attack_type, ip_counter, current_time, html_file='report.html', template_file='template.html'):
    attack_status = "Potential Attack Detected" if attack_type == 1 else "Normal"
    alert_message = f"Network traffic report for {current_time}. Attack status: {attack_status}."
    
    # Trouver l'IP principale (la première IP suspecte dans l'IP Counter)
    attacker_ip = next(iter(ip_counter), 'N/A')

    try:
        # Lire le template et remplir les données
        with open(template_file, 'r') as template_file:
            template_content = template_file.read()
            template = Template(template_content)
            # Si le fichier HTML existe déjà, on récupère son contenu
            try:
                with open(html_file, 'r') as file:
                    existing_content = file.read()
                # Remplacer les placeholders dans le template
                new_content = existing_content.replace('{alert_message}', alert_message).replace('{attacker_ip}', attacker_ip)
            except FileNotFoundError:
                # Si le fichier n'existe pas, créer un nouveau contenu avec le template
                new_content = template.render(alert_message=alert_message, attacker_ip=attacker_ip)

        with open(html_file, 'w') as file:
            file.write(new_content)

    except Exception as e:
        # Si une erreur survient (par exemple, fichier template non trouvé), utiliser le code de base
        with open(html_file, "a") as file:
            attack_status = "Potential Attack Detected" if attack_type == 1 else "Normal"
            ip_list = "<br>".join(ip_counter.keys())
            file.write(f"<tr><td>{current_time}</td><td>{ip_count}</td><td>{packet_rate:.2f}</td><td>{attack_status}</td><td>{ip_list}</td></tr>")

# block ip
def add_iptables_rule(block_ip):
    try:
        # Bloquer tout le trafic venant de l'IP
        cmd_block_input = ["sudo", "iptables", "-A", "INPUT", "-s", block_ip, "-j", "DROP"]
        cmd_block_forward = ["sudo", "iptables", "-A", "FORWARD", "-s", block_ip, "-j", "DROP"]

        # Supprimer les connexions établies existantes (optionnel mais recommandé pour une réponse immédiate)
        cmd_clear_conntrack = ["sudo", "conntrack", "-D", "-s", block_ip]

        # Appliquer les règles
        subprocess.run(cmd_block_input, capture_output=True, text=True, check=True)
        subprocess.run(cmd_block_forward, capture_output=True, text=True, check=True)
        subprocess.run(cmd_clear_conntrack, capture_output=True, text=True, check=True)

        return f"Tout le trafic de l'IP {block_ip} est maintenant bloqué."
    except subprocess.CalledProcessError as e:
        return f"Erreur lors de l'ajout des règles : {e.stderr}"



# Script principal
def main():
    blocked=[]
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
            # Identification de l'IP la plus active (potentiellement l'attaquant)
            attacker_ip = ip_counter.most_common(1)[0][0]
            alert_message = f"ALERT: Potential attack detected!\n\nStats:\nUnique IPs = {ip_count}\nPacket Rate = {packet_rate:.2f} packets/sec\nTime: {current_time}"
            print(f"\n{alert_message}\nIP suspecte principale : {attacker_ip}\n")
            if attacker_ip not in blocked:
                blocked.append(attacker_ip)
                print(add_iptables_rule(attacker_ip))
                send_email(alert_message, attacker_ip)
            else:
                print(f"IP {attacker_ip} already blocked.")
        else:
            print("\nTraffic appears normal.\n")

        # Écriture des résultats dans le fichier HTML
        write_to_html(ip_count, packet_rate, attack_type, ip_counter, current_time)

        # Attente avant la prochaine surveillance
        print("Waiting for the next monitoring cycle...\n")
        time.sleep(5)

if __name__ == "__main__":
    main()

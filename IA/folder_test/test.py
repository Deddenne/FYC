from scapy.all import ARP, Ether, srp, sniff
from collections import defaultdict

def get_all_ips():
    """
    Scanne le réseau sur toutes les interfaces disponibles et récupère toutes les IP connectées.
    """
    all_ips = set()
    
    # Liste toutes les interfaces
    from scapy.config import conf
    interfaces = conf.ifaces
    
    for iface_name in interfaces.data.keys():
        try:
            # Création d'une requête ARP pour chaque interface
            arp = ARP(pdst="192.168.1.0/24")  # Remplacez avec votre sous-réseau si nécessaire
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            result = srp(packet, timeout=2, iface=iface_name, verbose=False)[0]

            # Récupération des IP des réponses
            for _, received in result:
                all_ips.add(received.psrc)
        except Exception as e:
            print(f"Erreur sur l'interface {iface_name}: {e}")
    
    return list(all_ips)

def capture_traffic_for_ip(target_ip, duration=1):
    """
    Capture et affiche le trafic réseau pour une IP spécifique pendant un temps limité (par défaut 1 seconde).

    :param target_ip: L'adresse IP à surveiller
    :param duration: Durée en secondes pendant laquelle le trafic sera capturé (par défaut 1 seconde)
    """
    traffic_count = 0  # Compteur de trafic (en octets)

    def process_packet(packet):
        nonlocal traffic_count
        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst
            packet_size = len(packet)  # Taille du paquet en octets

            # Vérifier si l'IP est source ou destination
            if src_ip == target_ip or dst_ip == target_ip:
                traffic_count += packet_size

    print(f"Capture du trafic pour l'IP {target_ip} pendant {duration} seconde(s)...")

#Capture des paquets pendant une durée spécifique
    sniff(filter=f"ip host {target_ip}", prn=process_packet, store=False, timeout=duration)

    print(f"Trafic total pour {target_ip} pendant {duration} seconde(s) : {traffic_count} octets")


def main():
    print("Scan des IP sur le réseau...")
    while True:
        all_ips = get_all_ips()
        print(f"IP détectées : {all_ips}")
        if not all_ips:
            print("Aucune IP détectée sur le réseau.")
            return

        # Lancer la capture de trafic sur un thread séparé
        for ip in all_ips:
            capture_traffic_for_ip(ip)



if __name__ == "__main__":
    main()

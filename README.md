# Inquisitor

# Inquisitor Tool

# Description

Inquisitor est un outil d'analyse de réseau écrit en Python, utilisant la bibliothèque Scapy pour l'interception et l'analyse des paquets de données. Il permet de scanner le réseau local, d'usurper l'adresse IP d'un hôte cible (ARP spoofing) et de surveiller le trafic réseau en affichant des informations détaillées sur chaque paquet capturé.

# Prérequis

Vous devez avoir Python 3 installé sur votre machine. Vous aurez également besoin de la bibliothèque Scapy. Vous pouvez l'installer avec la commande suivante :

pip install scapy

# Utilisation

Pour utiliser Inquisitor, vous devez fournir les adresses IP et MAC source et cible. Vous pouvez également activer le mode verbeux pour obtenir des informations détaillées sur chaque paquet capturé.


python3 inquisitor.py [src_ip] [src_mac] [tgt_ip] [tgt_mac] [-v]
où :

src_ip est l'adresse IP source.
src_mac est l'adresse MAC source.
tgt_ip est l'adresse IP de la cible.
tgt_mac est l'adresse MAC de la cible.
-v est une option pour activer le mode verbeux.

# Fonctionnalités

ARP Scan : Le programme commence par scanner le réseau local pour trouver tous les hôtes connectés et affiche leurs adresses IP et MAC.
ARP Spoofing : Le programme usurpe ensuite l'adresse IP de l'hôte cible, le rendant ainsi visible sur le réseau comme si c'était l'hôte source.
Surveillance du réseau : Le programme surveille ensuite le trafic réseau, intercepte les paquets de données et affiche des informations détaillées sur chaque paquet.
Avertissement

L'utilisation de cet outil pour usurper l'identité d'autres hôtes sur le réseau sans permission est illégale. Ce programme est destiné à être utilisé dans un environnement de test ou pour l'apprentissage. Vous êtes responsable de l'utilisation que vous faites de cet outil.

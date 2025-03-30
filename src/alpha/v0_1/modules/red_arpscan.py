#!/usr/bin/env python3
# ARP Scan

import argparse
from scapy.all import ARP, Ether, srp
import sys
import signal

def arp_scan(ip_range):
    """
    Realiza uma varredura ARP no intervalo de IPs especificado.
    
    Parâmetros:
        ip_range (str): Intervalo de IPs no formato "192.168.1.0/24".
    
    Retorna:
        list: Lista de dicionários com IP e MAC dos dispositivos encontrados.
    """
    # Cria o pacote ARP e o encapsula em um pacote Ethernet (broadcast)
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    print(f"Iniciando varredura ARP no intervalo: {ip_range}")
    # Envia o pacote e coleta as respostas
    result = srp(packet, timeout=15, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

def print_devices(devices):
    """
    Exibe os dispositivos encontrados em formato tabular.
    """
    print("\nDispositivos encontrados:")
    print("IP\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t{device['mac']}")

def menu():
    """
    Modo interativo para inserir o intervalo de IPs via input.
    """
    ip_range = input("Digite o intervalo de IPs (ex: 192.168.1.0/24): ")
    devices = arp_scan(ip_range)
    print_devices(devices)

def terminal():
    """
    Modo via linha de comando, utilizando argumentos.
    """
    parser = argparse.ArgumentParser(
        description="Ferramenta de ARP Scan",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-i", "--ip_range", required=True, 
                        help="Intervalo de IPs (ex: 192.168.1.0/24)")
    
    args = parser.parse_args()
    devices = arp_scan(args.ip_range)
    print_devices(devices)

def signal_handler(sig, frame):
    """
    Trata o sinal de interrupção (Ctrl+C) para encerrar o programa de forma elegante.
    """
    print("\nEncerrando o ARP Scan...")
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    # Se houver argumentos na linha de comando, utiliza o modo terminal, senão entra no modo interativo.
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == "__main__":
    main()

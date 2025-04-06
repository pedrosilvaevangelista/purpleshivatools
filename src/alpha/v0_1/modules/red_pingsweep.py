#!/usr/bin/env python3
# Ping Sweep

import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Remove os avisos do Scapy
from scapy.all import IP, ICMP, sr1, send
import sys
import signal

def ping_sweep(ip_range):
    print(f"Iniciando Ping Sweep no intervalo: {ip_range}")
    active_hosts = []
    
    total_ips = 254  # Para intervalo /24, de 1 a 254
    # Percorre todos os IPs no /24
    for count, i in enumerate(range(1, 255), start=1):
        ip = f"192.168.1.{i}"
        pkt = IP(dst=ip)/ICMP()
        # Envia o pacote ICMP e aguarda a resposta
        response = sr1(pkt, timeout=1, verbose=False)
        
        if response:  # Se houver resposta, o host está ativo
            active_hosts.append(ip)
        
        # Calcula e exibe a porcentagem de conclusão
        progress = (count / total_ips) * 100
        sys.stdout.write(f"\rProgresso: {progress:.2f}%")
        sys.stdout.flush()
    
    print()  # Pula uma linha ao finalizar
    return active_hosts

def print_hosts(hosts):
    """
    Exibe os hosts ativos encontrados.
    """
    print("\nHosts ativos encontrados:")
    print("-----------------------------------------")
    for host in hosts:
        print(f"{host}")

def menu():
    """
    Modo interativo para inserir o intervalo de IPs via input.
    """
    ip_range = input("Digite o intervalo de IPs (ex: 192.168.1.0/24): ")
    hosts = ping_sweep(ip_range)
    print_hosts(hosts)

def terminal():
    """
    Modo via linha de comando, utilizando argumentos.
    """
    parser = argparse.ArgumentParser(
        description="Ferramenta de Ping Sweep",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-i", "--ip_range", required=True, 
                        help="Intervalo de IPs (ex: 192.168.1.0/24)")
    args = parser.parse_args()
    hosts = ping_sweep(args.ip_range)
    print_hosts(hosts)

def signal_handler(sig, frame):
    """
    Trata o sinal de interrupção (Ctrl+C) para encerrar o programa de forma elegante.
    """
    print("\nEncerrando o Ping Sweep...")
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    # Se houver argumentos na linha de comando, utiliza o modo terminal; caso contrário, o modo interativo.
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Remove os avisos do Scapy
from scapy.all import IP, ICMP, sr1, send
import sys
import signal

def ping_sweep(ip_range):
    """
    Realiza um Ping Sweep no intervalo de IPs especificado.

    Parâmetros:
        ip_range (str): Intervalo de IPs no formato "192.168.1.0/24".

    Retorna:
        list: Lista de IPs dos hosts ativos encontrados.
    """
    print(f"Iniciando Ping Sweep no intervalo: {ip_range}")
    active_hosts = []
    
    total_ips = 254  # Para intervalo /24, de 1 a 254
    ips = [f"192.168.1.{i}" for i in range(1, 255)]

    # Create ICMP packets for all IPs
    packets = [IP(dst=ip)/ICMP() for ip in ips]

    # Send packets in parallel and wait for responses
    answered, unanswered = sr(packets, timeout=1, verbose=False)

    # Extract active hosts
    active_hosts = [resp[0][IP].dst for resp in answered]

    print("Active Hosts:", active_hosts)
        
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

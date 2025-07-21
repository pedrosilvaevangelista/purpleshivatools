# utils.py
import subprocess
import socket
import struct
import re
import config as conf

def get_network_interfaces():
    """Lista todas as interfaces de rede disponíveis"""
    interfaces = []
    try:
        result = subprocess.run(['ip', 'link', 'show'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                match = re.search(r'\d+: (\w+):', line)
                if match and match.group(1) != 'lo':
                    interfaces.append(match.group(1))
    except:
        # Fallback para sistemas sem ip command
        try:
            import netifaces
            interfaces = [iface for iface in netifaces.interfaces() if iface != 'lo']
        except ImportError:
            interfaces = ['eth0', 'wlan0', 'enp0s3']
    
    return interfaces

def validate_interface(interface):
    """Valida se uma interface existe e está ativa"""
    try:
        result = subprocess.run(['ip', 'link', 'show', interface], 
                              capture_output=True, text=True, timeout=3)
        return result.returncode == 0
    except:
        return False

def get_interface_info(interface):
    """Obtém informações sobre uma interface"""
    info = {
        'name': interface,
        'status': 'unknown',
        'mac': 'unknown',
        'ip': 'unknown'
    }
    
    try:
        # Status da interface
        result = subprocess.run(['ip', 'link', 'show', interface], 
                              capture_output=True, text=True, timeout=3)
        if result.returncode == 0:
            if 'state UP' in result.stdout:
                info['status'] = 'up'
            elif 'state DOWN' in result.stdout:
                info['status'] = 'down'
            
            # MAC address
            mac_match = re.search(r'link/ether ([a-f0-9:]{17})', result.stdout)
            if mac_match:
                info['mac'] = mac_match.group(1)
        
        # IP address
        result = subprocess.run(['ip', 'addr', 'show', interface], 
                              capture_output=True, text=True, timeout=3)
        if result.returncode == 0:
            ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
            if ip_match:
                info['ip'] = ip_match.group(1)
                
    except:
        pass
    
    return info

def check_root_privileges():
    """Verifica se o script está rodando com privilégios root"""
    import os
    return os.geteuid() == 0

def check_dependencies():
    """Verifica se as dependências necessárias estão instaladas"""
    deps = {
        'scapy': False,
        'root': False,
        'interfaces': []
    }
    
    try:
        import scapy
        deps['scapy'] = True
    except ImportError:
        pass
    
    deps['root'] = check_root_privileges()
    deps['interfaces'] = get_network_interfaces()
    
    return deps

def print_system_info():
    """Imprime informações do sistema relevantes para o ataque"""
    print(f"\n{conf.PURPLE}{'='*50}{conf.RESET}")
    print(f"{conf.PURPLE}{conf.BOLD} INFORMAÇÕES DO SISTEMA {conf.RESET}")
    print(f"{conf.PURPLE}{'='*50}{conf.RESET}")
    
    deps = check_dependencies()
    
    # Privilégios
    if deps['root']:
        print(f"  Privilégios: {conf.GREEN}ROOT ✓{conf.RESET}")
    else:
        print(f"  Privilégios: {conf.RED}NÃO-ROOT ✗{conf.RESET}")
        print(f"    {conf.YELLOW}Aviso: Execute como root para funcionalidade completa{conf.RESET}")
    
    # Scapy
    if deps['scapy']:
        print(f"  Scapy: {conf.GREEN}INSTALADO ✓{conf.RESET}")
    else:
        print(f"  Scapy: {conf.RED}NÃO ENCONTRADO ✗{conf.RESET}")
        print(f"    {conf.YELLOW}Instale com: pip install scapy{conf.RESET}")
    
    # Interfaces
    print(f"\n{conf.PURPLE}Interfaces disponíveis:{conf.RESET}")
    if deps['interfaces']:
        for iface in deps['interfaces']:
            info = get_interface_info(iface)
            status_color = conf.GREEN if info['status'] == 'up' else conf.YELLOW
            print(f"  {iface}: {status_color}{info['status'].upper()}{conf.RESET} | "
                  f"MAC: {conf.CYAN}{info['mac']}{conf.RESET} | "
                  f"IP: {conf.CYAN}{info['ip']}{conf.RESET}")
    else:
        print(f"  {conf.RED}Nenhuma interface encontrada{conf.RESET}")
    
    return deps

def generate_random_mac():
    """Gera um MAC address aleatório válido"""
    import random
    # Usar OUI comum (primeiro octeto par para unicast)
    mac = [0x00, 0x16, 0x3e,  # VMware OUI
           random.randint(0x00, 0xff),
           random.randint(0x00, 0xff),
           random.randint(0x00, 0xff)]
    return ':'.join(['%02x' % x for x in mac])
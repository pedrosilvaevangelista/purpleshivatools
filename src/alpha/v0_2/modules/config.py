import subprocess
import re

# Colors
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[38;2;255;0;0m"         
GREEN = "\033[38;2;0;255;0m"       
YELLOW = "\033[38;2;255;255;0m"    
BLUE = "\033[38;2;0;0;255m"        
PURPLE = "\033[38;2;130;62;176m"   
CYAN = '\033[96m'
WHITE = "\033[97m"

logDir = "/var/log/purpleshivatools/"

def get_default_interface():
    """Obtém a interface de rede padrão do sistema"""
    try:
        # Tentar obter via route padrão
        result = subprocess.run(['ip', 'route', 'show', 'default'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            match = re.search(r'dev (\w+)', result.stdout)
            if match:
                return match.group(1)
        
        # Fallback: listar interfaces ativas
        result = subprocess.run(['ip', 'link', 'show'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            interfaces = re.findall(r'\d+: (\w+):', result.stdout)
            # Filtrar loopback
            interfaces = [iface for iface in interfaces if iface != 'lo']
            if interfaces:
                return interfaces[0]
                
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    # Fallback final
    return "eth0"
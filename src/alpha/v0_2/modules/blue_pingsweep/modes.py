import argparse
import sys 
from .pingsweep import PingSweep
from .report import write_json_log, write_xml_log
from .shell import PingSweepShell
from modules import config as conf
import os
import subprocess

PARAMS = [
    {"name": "IP RANGE", "key": "ip_range", "value": "", "desc": "Range de IPs (ex: 192.168.1.0/24)", "required": True},
    {"name": "DELAY", "key": "delay", "value": "0.1", "desc": "Delay entre pings (segundos)", "required": False},
    {"name": "THREADS", "key": "threads", "value": "50", "desc": "Número máximo de threads", "required": False},
    {"name": "REPORT FORMAT", "key": "report_format", "value": "json", "desc": "Formato da Exportação", "required": False},
    {"name": "VERBOSE", "key": "verbose", "value": "false", "desc": "Modo detalhado", "required": False},
]

def run_scan():
    """Direct scan execution for terminal mode"""
    config = {p["key"]: p["value"] for p in PARAMS}
    
    try:
        delay = float(config["delay"])
        threads = int(config["threads"])
        verbose = config["verbose"].lower() == "true"
        
        if not config["ip_range"]:
            print(f"{conf.RED}[!] IP range is required{conf.RESET}")
            return
        
        print(f"\n{conf.PURPLE}{'='*60}{conf.RESET}")
        print(f"{conf.PURPLE}{conf.BOLD} INICIANDO PINGSWEEP {conf.RESET}")
        print(f"{conf.PURPLE}{'='*60}{conf.RESET}")
        
        print(f"\n{conf.PURPLE}Configurações:{conf.RESET}")
        print(f"  Range: {conf.GREEN}{config['ip_range']}{conf.RESET}")
        print(f"  Delay: {conf.GREEN}{delay}s{conf.RESET}")
        print(f"  Threads: {conf.GREEN}{threads}{conf.RESET}")
        print(f"  Formato: {conf.GREEN}{config['report_format']}{conf.RESET}")
        print(f"  Verbose: {conf.GREEN}{verbose}{conf.RESET}")

        # Executar scan
        scanner = PingSweep(
            ip_range=config["ip_range"],
            delay=delay,
            verbose=verbose,
            max_threads=threads
        )
        
        result = scanner.scan()

        # Gerar relatório
        fmt = config["report_format"].lower()
        if fmt == "json":
            write_json_log(
                ip_range=result["ip_range"],
                total_hosts=result["total_hosts"],
                active_hosts=result["active_hosts"],
                duration=result["duration"]
            )
        elif fmt == "xml":
            write_xml_log(
                ip_range=result["ip_range"],
                total_hosts=result["total_hosts"],
                active_hosts=result["active_hosts"],
                duration=result["duration"]
            )
            
    except Exception as e:
        print(f"{conf.RED}[!] Erro durante execução: {e}{conf.RESET}")

def InteractiveMode():
    
    # Launch the new shell
    PingSweepShell(PARAMS)

def TerminalMode():
    """Terminal mode with command line arguments"""
    parser = argparse.ArgumentParser(
        description='PingSweep - Network Host Discovery Tool',
        prog='pingsweep',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  pingsweep -i 192.168.1.0/24
  pingsweep -i 192.168.1.1-192.168.1.100 -d 0.5 -t 100
  pingsweep -i 10.0.0.1 --format xml --verbose
  pingsweep --help
        '''
    )
    
    # Updated IP range argument with -i
    parser.add_argument(
        '-i', '--range', '--ip-range',  # -i is now the primary short option
        dest='ip_range',
        required=True,
        help='Target IP range (e.g., 192.168.1.0/24, 192.168.1.1-192.168.1.100, or single IP)'
    )
    
    # The rest of the arguments remain unchanged
    parser.add_argument(
        '-d', '--delay',
        type=float,
        default=0.1,
        help='Delay between ping attempts in seconds (default: 0.1)'
    )
    
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=50,
        help='Maximum number of threads (default: 50)'
    )
    
    parser.add_argument(
        '-f', '--format', '--report-format',
        dest='report_format',
        choices=['json', 'xml'],
        default='json',
        help='Output report format (default: json)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='PingSweep 1.0.0'
    )
    
    try:
        args = parser.parse_args()
    except SystemExit:
        return
    
    # Update PARAMS with command line arguments
    for param in PARAMS:
        if param['key'] == 'ip_range':
            param['value'] = args.ip_range
        elif param['key'] == 'delay':
            param['value'] = str(args.delay)
        elif param['key'] == 'threads':
            param['value'] = str(args.threads)
        elif param['key'] == 'report_format':
            param['value'] = args.report_format
        elif param['key'] == 'verbose':
            param['value'] = str(args.verbose).lower()
    
    # Run the scan
    run_scan()
    
def main():
    """Main entry point - determine mode based on arguments"""
    if len(sys.argv) > 1:
        # Terminal mode - has command line arguments
        TerminalMode()
    else:
        # Interactive mode - no arguments
        InteractiveMode()

if __name__ == "__main__":
    main()
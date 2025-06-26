import argparse
import sys 
from .portscan import PortScan
from .report import write_json_log, write_xml_log
from .shell import PortScanShell
from modules import config as conf
import os
import subprocess

PARAMS = [
    {"name": "TARGET IP", "key": "ip", "value": "", "desc": "Target IP address", "required": True},
    {"name": "PORT RANGE", "key": "port_range", "value": "", "desc": "Port range (e.g., 1-1000)", "required": True},
    {"name": "DELAY", "key": "delay", "value": "0.1", "desc": "Delay between attempts", "required": False},
    {"name": "REPORT FORMAT", "key": "report_format", "value": "json", "desc": "Export format", "required": False},
    {"name": "VERBOSE", "key": "verbose", "value": "false", "desc": "Verbose mode", "required": False},
]

def run_scan():
    """Run scan in direct terminal mode"""
    config = {p["key"]: p["value"] for p in PARAMS}
    
    try:
        delay = float(config["delay"])
        verbose = config["verbose"].lower() == "true"
        
        if not config["ip"]:
            print(f"{conf.RED}[!] Target IP is required{conf.RESET}")
            return
        
        if not config["port_range"]:
            print(f"{conf.RED}[!] Port range is required{conf.RESET}")
            return
        
        print(f"\n{conf.PURPLE}{'='*60}{conf.RESET}")
        print(f"{conf.PURPLE}{conf.BOLD} STARTING PORTSCAN {conf.RESET}")
        print(f"{conf.PURPLE}{'='*60}{conf.RESET}")
        
        print(f"\n{conf.PURPLE}Configuration:{conf.RESET}")
        print(f"  Target IP: {conf.GREEN}{config['ip']}{conf.RESET}")
        print(f"  Port Range: {conf.GREEN}{config['port_range']}{conf.RESET}")
        print(f"  Delay: {conf.GREEN}{delay}s{conf.RESET}")
        print(f"  Report Format: {conf.GREEN}{config['report_format']}{conf.RESET}")
        print(f"  Verbose: {conf.GREEN}{verbose}{conf.RESET}")

        # Execute scan
        scanner = PortScan(
            ip=config["ip"],
            port_range=config["port_range"],
            delay=delay,
            verbose=verbose
        )
        
        result = scanner.scan()

        # Generate report
        fmt = config["report_format"].lower()
        if fmt == "json":
            write_json_log(
                ip=result["ip"],
                total_ports=result["total_ports"],
                open_ports=result["open_ports"],
                duration=result["duration"]
            )
        elif fmt == "xml":
            write_xml_log(
                ip=result["ip"],
                total_ports=result["total_ports"],
                open_ports=result["open_ports"],
                duration=result["duration"]
            )
            
    except Exception as e:
        print(f"{conf.RED}[!] Error during execution: {e}{conf.RESET}")

def InteractiveMode():
    """Launch interactive shell mode"""
    PortScanShell(PARAMS)

def TerminalMode():
    """Terminal mode with command-line arguments"""
    parser = argparse.ArgumentParser(
        description='PortScan - Network Port Discovery Tool',
        prog='portscan',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
  portscan -i 192.168.1.1 -p 1-1000
  portscan -i 10.0.0.1 -p 80,443,8080 -d 0.5
  portscan -i 192.168.1.100 -p 1-65535 --format xml --verbose
  portscan --help
        '''
    )
    
    parser.add_argument(
        '-i', '--ip', '--target',
        dest='ip',
        required=True,
        help='Target IP address'
    )
    
    parser.add_argument(
        '-p', '--ports', '--port-range',
        dest='port_range',
        required=True,
        help='Port range (e.g., 1-1000, 80,443,8080, or single port)'
    )
    
    parser.add_argument(
        '-d', '--delay',
        type=float,
        default=0.1,
        help='Delay between scan attempts in seconds (default: 0.1)'
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
        version='PortScan 1.0.0'
    )
    
    try:
        args = parser.parse_args()
    except SystemExit:
        return
    
    for param in PARAMS:
        if param['key'] == 'ip':
            param['value'] = args.ip
        elif param['key'] == 'port_range':
            param['value'] = args.port_range
        elif param['key'] == 'delay':
            param['value'] = str(args.delay)
        elif param['key'] == 'report_format':
            param['value'] = args.report_format
        elif param['key'] == 'verbose':
            param['value'] = str(args.verbose).lower()
    
    run_scan()
    
def main():
    """Main entry point - determine mode based on arguments"""
    if len(sys.argv) > 1:
        TerminalMode()
    else:
        InteractiveMode()

if __name__ == "__main__":
    main()
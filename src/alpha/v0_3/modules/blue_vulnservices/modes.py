import argparse
import sys 
from .vulnservices import VulnerabilityScanner
from .report import write_json_log, write_xml_log
from .shell import VulnServicesShell
from modules import config as conf
import os
import subprocess

PARAMS = [
    {"name": "TARGET IP", "key": "target", "value": "", "desc": "Target IP address", "required": True},
    {"name": "PORT RANGE", "key": "ports", "value": "", "desc": "Port range (e.g., 1-1000)", "required": True},
    {"name": "SCAN TYPE", "key": "scan_type", "value": "tcp", "desc": "Type: tcp, udp, both", "required": False},
    {"name": "TIMING", "key": "timing", "value": "3", "desc": "Timing template (0-5)", "required": False},
    {"name": "REPORT FORMAT", "key": "report_format", "value": "json", "desc": "Export format", "required": False},
]

def run_scan():
    """Run scan in direct terminal mode"""
    config = {p["key"]: p["value"] for p in PARAMS}
    
    try:
        timing = int(config["timing"])
        
        if not config["target"]:
            print(f"{conf.RED}[!] Target IP is required{conf.RESET}")
            return
        
        if not config["ports"]:
            print(f"{conf.RED}[!] Port range is required{conf.RESET}")
            return
        
        print(f"\n{conf.PURPLE}{'='*60}{conf.RESET}")
        print(f"{conf.PURPLE}{conf.BOLD} STARTING VULNERABILITY SCAN {conf.RESET}")
        print(f"{conf.PURPLE}{'='*60}{conf.RESET}")
        
        print(f"\n{conf.PURPLE}Configuration:{conf.RESET}")
        print(f"  Target: {conf.GREEN}{config['target']}{conf.RESET}")
        print(f"  Ports: {conf.GREEN}{config['ports']}{conf.RESET}")
        print(f"  Scan Type: {conf.GREEN}{config['scan_type']}{conf.RESET}")
        print(f"  Timing: {conf.GREEN}T{timing}{conf.RESET}")
        print(f"  Report Format: {conf.GREEN}{config['report_format']}{conf.RESET}")

        # Execute scan
        scanner = VulnerabilityScanner(
            target=config["target"],
            ports=config["ports"],
            scan_type=config["scan_type"],
            timing=timing
        )
        
        result = scanner.scan()

        # Generate report
        fmt = config["report_format"].lower()
        if fmt == "json":
            write_json_log(result)
        elif fmt == "xml":
            write_xml_log(result)
            
    except Exception as e:
        print(f"{conf.RED}[!] Error during execution: {e}{conf.RESET}")

def InteractiveMode():
    """Launch interactive shell mode"""
    VulnServicesShell(PARAMS)

def TerminalMode():
    """Terminal mode with command-line arguments"""
    parser = argparse.ArgumentParser(
        description='VulnServices - Vulnerability Scanner Tool',
        prog='vulnservices',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
  vulnservices -t 192.168.1.100 -p 1-1000
  vulnservices -t 10.0.0.1 -p 80,443,8080 --scan-type both
  vulnservices -t 192.168.1.1 -p 1-65535 --timing 4 --format xml
  vulnservices --help
        '''
    )
    
    parser.add_argument(
        '-t', '--target',
        required=True,
        help='Target IP address'
    )
    
    parser.add_argument(
        '-p', '--ports',
        required=True,
        help='Port range (e.g., 1-1000, 80,443, or single port)'
    )
    
    parser.add_argument(
        '-s', '--scan-type',
        dest='scan_type',
        choices=['tcp', 'udp', 'both'],
        default='tcp',
        help='Scan type (default: tcp)'
    )
    
    parser.add_argument(
        '--timing',
        type=int,
        choices=range(6),
        default=3,
        help='Timing template 0-5 (default: 3)'
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
        version='VulnServices 1.0.0'
    )
    
    try:
        args = parser.parse_args()
    except SystemExit:
        return
    
    for param in PARAMS:
        if param['key'] == 'target':
            param['value'] = args.target
        elif param['key'] == 'ports':
            param['value'] = args.ports
        elif param['key'] == 'scan_type':
            param['value'] = args.scan_type
        elif param['key'] == 'timing':
            param['value'] = str(args.timing)
        elif param['key'] == 'report_format':
            param['value'] = args.report_format
    
    run_scan()
    
def main():
    """Main entry point - determine mode based on arguments"""
    if len(sys.argv) > 1:
        TerminalMode()
    else:
        InteractiveMode()

if __name__ == "__main__":
    main()
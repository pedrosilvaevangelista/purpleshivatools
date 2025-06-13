# modes.py
import argparse
import sys
from .vulnservices import VulnerabilityScanner
from .report import write_json_log, write_xml_log
import config as conf
from . import help

PARAMS = [
    {"name": "TARGET IP", "key": "target", "value": "", "desc": "IP do alvo", "required": True},
    {"name": "PORT RANGE", "key": "ports", "value": "", "desc": "Intervalo de portas (ex: 1-1000)", "required": True},
    {"name": "SCAN TYPE", "key": "scan_type", "value": "tcp", "desc": "Tipo: tcp, udp, both", "required": False},
    {"name": "TIMING", "key": "timing", "value": "3", "desc": "Template timing (0-5)", "required": False},
    {"name": "REPORT FORMAT", "key": "report_format", "value": "json", "desc": "Formato: json, xml", "required": False},
]

def print_help():
    try:
        help.print_help()
    except Exception as e:
        print(f"{conf.RED}Erro ao mostrar ajuda: {e}{conf.RESET}")

def print_table():
    col_widths = {
        'num': 4,
        'name': max(len(p['name']) for p in PARAMS) + 2,
        'value': max(len(p['value']) if p['value'] else len('não definido') for p in PARAMS) + 2,
        'desc': max(len(p['desc']) for p in PARAMS) + 2,
        'req': 8
    }
    
    col_widths['name'] = max(col_widths['name'], 17)
    col_widths['value'] = max(col_widths['value'], 20)
    col_widths['desc'] = max(col_widths['desc'], 26)
    
    separator = f"{conf.PURPLE}+{'-' * col_widths['num']}+{'-' * col_widths['name']}+{'-' * col_widths['value']}+{'-' * col_widths['desc']}+{'-' * col_widths['req']}+{conf.RESET}"
    print(f"\n{separator}")
    
    header = f"{conf.PURPLE}|{conf.RESET} {'N°':<{col_widths['num']-1}}{conf.PURPLE}|{conf.RESET} {'OPÇÃO':<{col_widths['name']-1}}{conf.PURPLE}|{conf.RESET} {'VALOR':<{col_widths['value']-1}}{conf.PURPLE}|{conf.RESET} {'DESCRIÇÃO':<{col_widths['desc']-1}}{conf.PURPLE}|{conf.RESET} {'STATUS':<{col_widths['req']-1}}{conf.PURPLE}|{conf.RESET}"
    print(header)
    print(separator)
    
    for i, p in enumerate(PARAMS):
        value_raw = p['value'] if p['value'] else 'não definido'
        value_display = f"{conf.GREEN}{value_raw}{conf.RESET}" if p['value'] else f"{conf.YELLOW}{value_raw}{conf.RESET}"
        status = f"{conf.RED}OBRIG.{conf.RESET}" if p['required'] else f"{conf.BLUE}OPCL. {conf.RESET}"
        
        value_padding = col_widths['value'] - len(value_raw) - 1
        status_padding = col_widths['req'] - 6 - 1
        
        row = f"{conf.PURPLE}|{conf.RESET} {i:<{col_widths['num']-1}}{conf.PURPLE}|{conf.RESET} {p['name']:<{col_widths['name']-1}}{conf.PURPLE}|{conf.RESET} {value_display}{' ' * value_padding}{conf.PURPLE}|{conf.RESET} {p['desc']:<{col_widths['desc']-1}}{conf.PURPLE}|{conf.RESET} {status}{' ' * status_padding}{conf.PURPLE}|{conf.RESET}"
        print(row)
    
    print(separator)

def InteractiveMode():
    print(f"\n{conf.PURPLE}{conf.BOLD}+{'-'*75}+{conf.RESET}")
    print(f"{conf.PURPLE}{conf.BOLD}|{'VULNERABILITY SCANNER - PURPLE SHIVA TOOLS':^75}|{conf.RESET}")
    print(f"{conf.PURPLE}{conf.BOLD}+{'-'*75}+{conf.RESET}")

    while True:
        print_table()
        print(f"\n{conf.PURPLE}[?] Digite o número da opção para editar, ou comando:{conf.RESET}")
        print(f"  {conf.GREEN}HELP{conf.RESET}  → Ver instruções")
        print(f"  {conf.GREEN}START{conf.RESET} → Iniciar scan com os parâmetros atuais")
        print(f"  {conf.RED}QUIT{conf.RESET}  → Sair da aplicação\n")

        cmd = input(f"{conf.PURPLE}{conf.BOLD}PurpleShivaTools > {conf.RESET}").strip().upper()
        
        if cmd == "HELP":
            print_help()
        elif cmd == "QUIT":
            print(f"{conf.YELLOW}Saindo...{conf.RESET}")
            break
        elif cmd == "START":
            missing = []
            for p in PARAMS:
                if p["required"] and not p["value"]:
                    missing.append(p["name"])
            
            if missing:
                print(f"{conf.RED}[!] Parâmetros obrigatórios não definidos: {', '.join(missing)}{conf.RESET}")
            else:
                run_scan()
                break
        elif cmd.isdigit() and int(cmd) in range(len(PARAMS)):
            idx = int(cmd)
            print(f"\n{conf.PURPLE}Configurando: {PARAMS[idx]['name']}{conf.RESET}")
            print(f"{conf.YELLOW}Descrição: {PARAMS[idx]['desc']}{conf.RESET}")
            
            if PARAMS[idx]["key"] == "scan_type":
                print(f"{conf.YELLOW}Opções: tcp, udp, both{conf.RESET}")
            elif PARAMS[idx]["key"] == "timing":
                print(f"{conf.YELLOW}Opções: 0(paranoid) a 5(insane){conf.RESET}")
            elif PARAMS[idx]["key"] == "report_format":
                print(f"{conf.YELLOW}Opções: json, xml{conf.RESET}")
            elif PARAMS[idx]["key"] == "ports":
                print(f"{conf.YELLOW}Exemplos: 80, 80-443, 1-1000{conf.RESET}")
            
            current_value = PARAMS[idx]['value'] if PARAMS[idx]['value'] else "não definido"
            new_value = input(f"Novo valor para {PARAMS[idx]['name']} (atual: {current_value}): ").strip()
            
            if new_value:
                if PARAMS[idx]["key"] == "timing":
                    try:
                        timing_val = int(new_value)
                        if timing_val not in range(6):
                            print(f"{conf.RED}[!] Timing deve ser entre 0-5{conf.RESET}")
                            continue
                    except ValueError:
                        print(f"{conf.RED}[!] Timing deve ser um número{conf.RESET}")
                        continue
                elif PARAMS[idx]["key"] == "scan_type" and new_value.lower() not in ["tcp", "udp", "both"]:
                    print(f"{conf.RED}[!] Tipo inválido. Use: tcp, udp ou both{conf.RESET}")
                    continue
                elif PARAMS[idx]["key"] == "report_format" and new_value.lower() not in ["json", "xml"]:
                    print(f"{conf.RED}[!] Formato inválido. Use: json ou xml{conf.RESET}")
                    continue
                
                PARAMS[idx]["value"] = new_value
                print(f"{conf.GREEN}[✓] Parâmetro atualizado com sucesso!{conf.RESET}")
        else:
            print(f"{conf.RED}[!] Entrada inválida.{conf.RESET}")

def run_scan():
    config = {p["key"]: p["value"] for p in PARAMS}
    
    try:
        timing = int(config["timing"])
        
        print(f"\n{conf.PURPLE}{'='*60}{conf.RESET}")
        print(f"{conf.PURPLE}{conf.BOLD} INICIANDO VULNERABILITY SCAN {conf.RESET}")
        print(f"{conf.PURPLE}{'='*60}{conf.RESET}")
        
        print(f"\n{conf.PURPLE}Configurações:{conf.RESET}")
        print(f"  Alvo: {conf.GREEN}{config['target']}{conf.RESET}")
        print(f"  Portas: {conf.GREEN}{config['ports']}{conf.RESET}")
        print(f"  Tipo: {conf.GREEN}{config['scan_type']}{conf.RESET}")
        print(f"  Timing: {conf.GREEN}T{timing}{conf.RESET}")
        print(f"  Formato: {conf.GREEN}{config['report_format']}{conf.RESET}")

        scanner = VulnerabilityScanner(
            target=config["target"],
            ports=config["ports"],
            scan_type=config["scan_type"],
            timing=timing
        )
        
        result = scanner.scan()

        fmt = config["report_format"].lower()
        if fmt == "json":
            write_json_log(result)
        elif fmt == "xml":
            write_xml_log(result)
            
    except Exception as e:
        print(f"{conf.RED}[!] Erro durante execução: {e}{conf.RESET}")

def command_line_mode():
    parser = argparse.ArgumentParser(description="Vulnerability Scanner - Purple Shiva Tools")
    parser.add_argument("-t", "--target", required=True, help="IP do alvo")
    parser.add_argument("-p", "--ports", required=True, help="Intervalo de portas")
    parser.add_argument("-s", "--scan-type", default="tcp", choices=["tcp", "udp", "both"], help="Tipo de scan")
    parser.add_argument("--timing", type=int, default=3, choices=range(6), help="Template timing")
    parser.add_argument("-r", "--report", default="json", choices=["json", "xml"], help="Formato do relatório")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo detalhado")

    args = parser.parse_args()

    param_map = {
        "target": args.target,
        "ports": args.ports,
        "scan_type": args.scan_type,
        "timing": str(args.timing),
        "report_format": args.report
    }

    for p in PARAMS:
        if p["key"] in param_map:
            p["value"] = param_map[p["key"]]

    run_scan()

def main():
    if len(sys.argv) == 1:
        InteractiveMode()
    else:
        command_line_mode()

if __name__ == "__main__":
    main()
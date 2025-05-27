# modes.py
import argparse
import sys
from .portscan import PortScan
from .report import write_json_log, write_xml_log
import config as conf
from . import help

PARAMS = [
    {"name": "TARGET IP", "key": "ip", "value": "", "desc": "IP do alvo", "required": True},
    {"name": "PORT RANGE", "key": "port_range", "value": "1-1000", "desc": "Intervalo (ex: 1-1000)", "required": True},
    {"name": "DELAY", "key": "delay", "value": "0.1", "desc": "Delay entre tentativas", "required": False},
    {"name": "REPORT FORMAT", "key": "report_format", "value": "json", "desc": "Formato: json, xml", "required": False},
    {"name": "VERBOSE", "key": "verbose", "value": "false", "desc": "Modo detalhado", "required": False},
]

def print_help():
    try:
        help.print_help()
    except Exception as e:
        print(f"{conf.RED}Erro ao mostrar ajuda: {e}{conf.RESET}")

def print_table():
    # Calcula larguras dinamicamente
    col_widths = {
        'num': 4,
        'name': max(len(p['name']) for p in PARAMS) + 2,
        'value': max(len(p['value']) if p['value'] else len('não definido') for p in PARAMS) + 2,
        'desc': max(len(p['desc']) for p in PARAMS) + 2,
        'req': 8
    }
    
    # Garante largura mínima
    col_widths['name'] = max(col_widths['name'], 17)
    col_widths['value'] = max(col_widths['value'], 20)
    col_widths['desc'] = max(col_widths['desc'], 26)
    
    # Cabeçalho
    separator = f"{conf.PURPLE}+{'-' * col_widths['num']}+{'-' * col_widths['name']}+{'-' * col_widths['value']}+{'-' * col_widths['desc']}+{'-' * col_widths['req']}+{conf.RESET}"
    print(f"\n{separator}")
    
    header = f"{conf.PURPLE}|{conf.RESET} {'N°':<{col_widths['num']-1}}{conf.PURPLE}|{conf.RESET} {'OPÇÃO':<{col_widths['name']-1}}{conf.PURPLE}|{conf.RESET} {'VALOR':<{col_widths['value']-1}}{conf.PURPLE}|{conf.RESET} {'DESCRIÇÃO':<{col_widths['desc']-1}}{conf.PURPLE}|{conf.RESET} {'STATUS':<{col_widths['req']-1}}{conf.PURPLE}|{conf.RESET}"
    print(header)
    print(separator)
    
    # Linhas da tabela
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
    print(f"{conf.PURPLE}{conf.BOLD}|{'PORTSCAN - PURPLE SHIVA TOOLS':^75}|{conf.RESET}")
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
            # Validação antes de iniciar
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
            
            # Dicas específicas
            if PARAMS[idx]["key"] == "report_format":
                print(f"{conf.YELLOW}Opções disponíveis: json, xml{conf.RESET}")
            elif PARAMS[idx]["key"] == "delay":
                print(f"{conf.YELLOW}Recomendado: 0.1 a 2.0 segundos{conf.RESET}")
            elif PARAMS[idx]["key"] == "port_range":
                print(f"{conf.YELLOW}Exemplos: 80, 1-1000, 80-443{conf.RESET}")
            elif PARAMS[idx]["key"] == "verbose":
                print(f"{conf.YELLOW}Opções: true ou false{conf.RESET}")
            
            current_value = PARAMS[idx]['value'] if PARAMS[idx]['value'] else "não definido"
            new_value = input(f"Novo valor para {PARAMS[idx]['name']} (atual: {current_value}): ").strip()
            
            if new_value:
                # Validação básica
                if PARAMS[idx]["key"] == "delay":
                    try:
                        float(new_value)
                    except ValueError:
                        print(f"{conf.RED}[!] Valor inválido para delay. Use números (ex: 0.1){conf.RESET}")
                        continue
                elif PARAMS[idx]["key"] == "report_format" and new_value.lower() not in ["json", "xml"]:
                    print(f"{conf.RED}[!] Formato inválido. Use: json ou xml{conf.RESET}")
                    continue
                elif PARAMS[idx]["key"] == "verbose" and new_value.lower() not in ["true", "false"]:
                    print(f"{conf.RED}[!] Valor inválido. Use: true ou false{conf.RESET}")
                    continue
                
                PARAMS[idx]["value"] = new_value
                print(f"{conf.GREEN}[✓] Parâmetro atualizado com sucesso!{conf.RESET}")
        else:
            print(f"{conf.RED}[!] Entrada inválida.{conf.RESET}")

def run_scan():
    config = {p["key"]: p["value"] for p in PARAMS}
    
    try:
        delay = float(config["delay"])
        verbose = config["verbose"].lower() == "true"
        
        print(f"\n{conf.PURPLE}{'='*60}{conf.RESET}")
        print(f"{conf.PURPLE}{conf.BOLD} INICIANDO PORTSCAN {conf.RESET}")
        print(f"{conf.PURPLE}{'='*60}{conf.RESET}")
        
        print(f"\n{conf.PURPLE}Configurações:{conf.RESET}")
        print(f"  Alvo: {conf.GREEN}{config['ip']}{conf.RESET}")
        print(f"  Portas: {conf.GREEN}{config['port_range']}{conf.RESET}")
        print(f"  Delay: {conf.GREEN}{delay}s{conf.RESET}")
        print(f"  Formato: {conf.GREEN}{config['report_format']}{conf.RESET}")
        print(f"  Verbose: {conf.GREEN}{verbose}{conf.RESET}")

        # Executar scan
        scanner = PortScan(
            ip=config["ip"],
            port_range=config["port_range"],
            delay=delay,
            verbose=verbose
        )
        
        result = scanner.scan()

        # Gerar relatório
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
        print(f"{conf.RED}[!] Erro durante execução: {e}{conf.RESET}")

def command_line_mode():
    parser = argparse.ArgumentParser(description="PortScan - Purple Shiva Tools")
    parser.add_argument("-i", "--ip", required=True, help="IP do alvo")
    parser.add_argument("-p", "--ports", required=True, help="Intervalo de portas (ex: 1-1000)")
    parser.add_argument("-d", "--delay", type=float, default=0.1, help="Delay entre tentativas")
    parser.add_argument("-r", "--report", default="json", choices=["json", "xml"], help="Formato do relatório")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo detalhado")

    args = parser.parse_args()

    # Atualizar PARAMS com argumentos da linha de comando
    param_map = {
        "ip": args.ip,
        "port_range": args.ports,
        "delay": str(args.delay),
        "report_format": args.report,
        "verbose": str(args.verbose).lower()
    }

    # Atualizar PARAMS
    for p in PARAMS:
        if p["key"] in param_map:
            p["value"] = param_map[p["key"]]

    run_scan()

def main():
    if len(sys.argv) == 1:
        # Modo interativo se não houver argumentos
        InteractiveMode()
    else:
        # Modo linha de comando
        command_line_mode()

if __name__ == "__main__":
    main()

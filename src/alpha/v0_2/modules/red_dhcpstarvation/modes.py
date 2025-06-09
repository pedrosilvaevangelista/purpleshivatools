# modes.py
import argparse
import sys
from .dhcpstarvation import DHCPStarvation
from .report import write_json_log, write_xml_log
import config as conf
from . import help

PARAMS = [
    {"name": "INTERFACE", "key": "interface", "value": "", "desc": "Interface de rede (ex: eth0, wlan0)", "required": True},
    {"name": "DELAY", "key": "delay", "value": "0.1", "desc": "Delay entre pacotes (segundos)", "required": False},
    {"name": "DURATION", "key": "duration", "value": "", "desc": "Duração do ataque (segundos)", "required": False},
    {"name": "VERBOSE", "key": "verbose", "value": "false", "desc": "Modo verboso (true/false)", "required": False},
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
    print(f"{conf.PURPLE}{conf.BOLD}|{'DHCP STARVATION - PURPLE SHIVA TOOLS':^75}|{conf.RESET}")
    print(f"{conf.PURPLE}{conf.BOLD}+{'-'*75}+{conf.RESET}")

    while True:
        print_table()
        print(f"\n{conf.PURPLE}[?] Digite o número da opção para editar, ou comando:{conf.RESET}")
        print(f"  {conf.GREEN}HELP{conf.RESET}  → Ver instruções")
        print(f"  {conf.GREEN}START{conf.RESET} → Iniciar ataque com os parâmetros atuais")
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
                run_attack()
                break
        elif cmd.isdigit() and int(cmd) in range(len(PARAMS)):
            idx = int(cmd)
            print(f"\n{conf.PURPLE}Configurando: {PARAMS[idx]['name']}{conf.RESET}")
            print(f"{conf.YELLOW}Descrição: {PARAMS[idx]['desc']}{conf.RESET}")
            
            if PARAMS[idx]["key"] == "interface":
                print(f"{conf.YELLOW}Dica: Use 'ip link show' para listar interfaces{conf.RESET}")
            elif PARAMS[idx]["key"] == "report_format":
                print(f"{conf.YELLOW}Opções disponíveis: json, xml{conf.RESET}")
            elif PARAMS[idx]["key"] == "delay":
                print(f"{conf.YELLOW}Recomendado: 0.01 a 1.0 segundos{conf.RESET}")
            elif PARAMS[idx]["key"] == "duration":
                print(f"{conf.YELLOW}Deixe vazio para duração ilimitada{conf.RESET}")
            elif PARAMS[idx]["key"] == "verbose":
                print(f"{conf.YELLOW}Opções: true ou false{conf.RESET}")
            
            current_value = PARAMS[idx]['value'] if PARAMS[idx]['value'] else "não definido"
            new_value = input(f"Novo valor para {PARAMS[idx]['name']} (atual: {current_value}): ").strip()
            
            if new_value:
                if PARAMS[idx]["key"] == "delay":
                    try:
                        float(new_value)
                    except ValueError:
                        print(f"{conf.RED}[!] Valor inválido para delay. Use números (ex: 0.1){conf.RESET}")
                        continue
                elif PARAMS[idx]["key"] == "duration":
                    try:
                        if new_value:
                            int(new_value)
                    except ValueError:
                        print(f"{conf.RED}[!] Valor inválido para duração. Use números inteiros{conf.RESET}")
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

def run_attack():
    config = {p["key"]: p["value"] for p in PARAMS}
    
    try:
        delay = float(config["delay"])
        verbose = config["verbose"].lower() == "true"
        duration = int(config["duration"]) if config["duration"] else None
        
        attacker = DHCPStarvation(
            interface=config["interface"],
            delay=delay,
            verbose=verbose
        )
        
        result = attacker.start_attack(duration=duration)

        # Gerar relatório
        fmt = config["report_format"].lower()
        if fmt == "json":
            write_json_log(
                interface=config["interface"],
                requests_sent=result["requests_sent"],
                responses_received=result["responses_received"],
                allocated_ips=result["allocated_ips"],
                duration=result["duration"]
            )
        elif fmt == "xml":
            write_xml_log(
                interface=config["interface"],
                requests_sent=result["requests_sent"],
                responses_received=result["responses_received"],
                allocated_ips=result["allocated_ips"],
                duration=result["duration"]
            )
            
    except Exception as e:
        print(f"{conf.RED}[!] Erro durante execução: {e}{conf.RESET}")

def command_line_mode():
    parser = argparse.ArgumentParser(description="DHCP Starvation Attack - Purple Shiva Tools")
    parser.add_argument("-i", "--interface", required=True, help="Interface de rede")
    parser.add_argument("-d", "--delay", type=float, default=0.1, help="Delay entre pacotes")
    parser.add_argument("-t", "--duration", type=int, help="Duração do ataque em segundos")
    parser.add_argument("-r", "--report", default="json", choices=["json", "xml"], help="Formato do relatório")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo verboso")

    args = parser.parse_args()

    param_map = {
        "interface": args.interface,
        "delay": str(args.delay),
        "duration": str(args.duration) if args.duration else "",
        "report_format": args.report,
        "verbose": str(args.verbose).lower()
    }

    for p in PARAMS:
        if p["key"] in param_map:
            p["value"] = param_map[p["key"]]

    run_attack()

def main():
    if len(sys.argv) == 1:
        InteractiveMode()
    else:
        command_line_mode()

if __name__ == "__main__":
    main()
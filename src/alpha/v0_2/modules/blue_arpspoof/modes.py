# modes.py
import argparse
import sys
from .arpspoof import ARPSpoof
from .report import write_json_log, write_xml_log
import config as conf
from . import help

PARAMS = [
    {"name": "TARGET IP", "key": "target_ip", "value": "", "desc": "IP do alvo para spoofing", "required": True},
    {"name": "GATEWAY IP", "key": "gateway_ip", "value": "", "desc": "IP do gateway (auto se vazio)", "required": False},
    {"name": "INTERFACE", "key": "interface", "value": "", "desc": "Interface de rede (auto se vazio)", "required": False},
    {"name": "DELAY", "key": "delay", "value": "2", "desc": "Delay entre pacotes ARP", "required": False},
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
    print(f"{conf.PURPLE}{conf.BOLD}|{'ARP SPOOF - PURPLE SHIVA TOOLS':^75}|{conf.RESET}")
    print(f"{conf.PURPLE}{conf.BOLD}+{'-'*75}+{conf.RESET}")

    while True:
        print_table()
        print(f"\n{conf.PURPLE}[?] Digite o número da opção para editar, ou comando:{conf.RESET}")
        print(f"  {conf.GREEN}HELP{conf.RESET}  → Ver instruções")
        print(f"  {conf.GREEN}START{conf.RESET} → Iniciar ARP Spoof com os parâmetros atuais")
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
                run_arpspoof()
                break
        elif cmd.isdigit() and int(cmd) in range(len(PARAMS)):
            idx = int(cmd)
            print(f"\n{conf.PURPLE}Configurando: {PARAMS[idx]['name']}{conf.RESET}")
            print(f"{conf.YELLOW}Descrição: {PARAMS[idx]['desc']}{conf.RESET}")
            
            if PARAMS[idx]["key"] == "report_format":
                print(f"{conf.YELLOW}Opções disponíveis: json, xml{conf.RESET}")
            elif PARAMS[idx]["key"] == "delay":
                print(f"{conf.YELLOW}Recomendado: 1 a 5 segundos{conf.RESET}")
            elif PARAMS[idx]["key"] == "target_ip":
                print(f"{conf.YELLOW}Exemplo: 192.168.1.100{conf.RESET}")
            
            current_value = PARAMS[idx]['value'] if PARAMS[idx]['value'] else "não definido"
            new_value = input(f"Novo valor para {PARAMS[idx]['name']} (atual: {current_value}): ").strip()
            
            if new_value:
                if PARAMS[idx]["key"] == "delay":
                    try:
                        float(new_value)
                    except ValueError:
                        print(f"{conf.RED}[!] Valor inválido para delay. Use números (ex: 2){conf.RESET}")
                        continue
                elif PARAMS[idx]["key"] == "report_format" and new_value.lower() not in ["json", "xml"]:
                    print(f"{conf.RED}[!] Formato inválido. Use: json ou xml{conf.RESET}")
                    continue
                
                PARAMS[idx]["value"] = new_value
                print(f"{conf.GREEN}[✓] Parâmetro atualizado com sucesso!{conf.RESET}")
        else:
            print(f"{conf.RED}[!] Entrada inválida.{conf.RESET}")

def run_arpspoof():
    config = {p["key"]: p["value"] for p in PARAMS}
    
    try:
        delay = float(config["delay"])
        
        print(f"\n{conf.PURPLE}{'='*60}{conf.RESET}")
        print(f"{conf.PURPLE}{conf.BOLD} INICIANDO ARP SPOOF {conf.RESET}")
        print(f"{conf.PURPLE}{'='*60}{conf.RESET}")
        
        print(f"\n{conf.PURPLE}Configurações:{conf.RESET}")
        print(f"  Alvo: {conf.GREEN}{config['target_ip']}{conf.RESET}")
        print(f"  Gateway: {conf.GREEN}{config['gateway_ip'] or 'Auto-detect'}{conf.RESET}")
        print(f"  Interface: {conf.GREEN}{config['interface'] or 'Auto-detect'}{conf.RESET}")
        print(f"  Delay: {conf.GREEN}{delay}s{conf.RESET}")
        print(f"  Formato: {conf.GREEN}{config['report_format']}{conf.RESET}")

        spoofer = ARPSpoof(
            target_ip=config["target_ip"],
            gateway_ip=config["gateway_ip"] if config["gateway_ip"] else None,
            interface=config["interface"] if config["interface"] else None,
            delay=delay
        )
        
        spoofer.run()

        fmt = config["report_format"].lower()
        if fmt == "json":
            write_json_log(
                target_ip=config["target_ip"],
                packets_captured=spoofer.packets_captured,
                gateway_ip=spoofer.gateway_ip,
                duration=0
            )
        elif fmt == "xml":
            write_xml_log(
                target_ip=config["target_ip"],
                packets_captured=spoofer.packets_captured,
                gateway_ip=spoofer.gateway_ip,
                duration=0
            )
            
    except Exception as e:
        print(f"{conf.RED}[!] Erro durante execução: {e}{conf.RESET}")

def command_line_mode():
    parser = argparse.ArgumentParser(description="ARP Spoof - Purple Shiva Tools")
    parser.add_argument("-t", "--target", required=True, help="IP do alvo")
    parser.add_argument("-g", "--gateway", help="IP do gateway")
    parser.add_argument("-i", "--interface", help="Interface de rede")
    parser.add_argument("-d", "--delay", type=float, default=2, help="Delay entre pacotes ARP")
    parser.add_argument("-r", "--report", default="json", choices=["json", "xml"], help="Formato do relatório")

    args = parser.parse_args()

    param_map = {
        "target_ip": args.target,
        "gateway_ip": args.gateway or "",
        "interface": args.interface or "",
        "delay": str(args.delay),
        "report_format": args.report
    }

    for p in PARAMS:
        if p["key"] in param_map:
            p["value"] = param_map[p["key"]]

    run_arpspoof()

def main():
    if len(sys.argv) == 1:
        InteractiveMode()
    else:
        command_line_mode()

if __name__ == "__main__":
    main()
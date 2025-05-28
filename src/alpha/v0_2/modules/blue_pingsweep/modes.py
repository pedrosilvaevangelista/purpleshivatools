# modes.py
import argparse
import sys
from .pingsweep import PingSweep
from .report import write_json_log, write_xml_log
import config as conf
from .help import print_help as help_print_help

PARAMS = [
    {"name": "IP RANGE", "key": "ip_range", "value": "", "desc": "Range de IPs (ex: 192.168.1.0/24)", "required": True},
    {"name": "DELAY", "key": "delay", "value": "0.1", "desc": "Delay entre pings (segundos)", "required": False},
    {"name": "THREADS", "key": "threads", "value": "50", "desc": "Número máximo de threads", "required": False},
    {"name": "REPORT FORMAT", "key": "report_format", "value": "json", "desc": "Formato: json, xml", "required": False},
    {"name": "VERBOSE", "key": "verbose", "value": "false", "desc": "Modo detalhado", "required": False},
]

def print_help():
    try:
        help_print_help()
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
    col_widths['desc'] = max(col_widths['desc'], 30)
    
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
    print(f"{conf.PURPLE}{conf.BOLD}|{'PING SWEEP SCANNER - PURPLE SHIVA TOOLS':^75}|{conf.RESET}")
    print(f"{conf.PURPLE}{conf.BOLD}+{'-'*75}+{conf.RESET}")

    while True:
        print_table()
        print(f"\n{conf.PURPLE}[?] Digite o número da opção para editar, ou comando:{conf.RESET}")
        print(f"  {conf.GREEN}HELP{conf.RESET}   → Ver instruções detalhadas")
        print(f"  {conf.GREEN}START{conf.RESET}  → Iniciar ping sweep")
        print(f"  {conf.GREEN}QUICK{conf.RESET}  → Scan rápido (primeiros 10 hosts)")
        print(f"  {conf.RED}QUIT{conf.RESET}   → Sair da aplicação\n")

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
        elif cmd == "QUICK":
            # Validação do IP range para scan rápido
            ip_range = next((p["value"] for p in PARAMS if p["key"] == "ip_range"), "")
            if not ip_range:
                print(f"{conf.RED}[!] Defina o IP RANGE primeiro{conf.RESET}")
            else:
                run_quick_scan()
        elif cmd.isdigit() and int(cmd) in range(len(PARAMS)):
            idx = int(cmd)
            print(f"\n{conf.PURPLE}Configurando: {PARAMS[idx]['name']}{conf.RESET}")
            print(f"{conf.YELLOW}Descrição: {PARAMS[idx]['desc']}{conf.RESET}")
            
            # Dicas específicas
            if PARAMS[idx]["key"] == "ip_range":
                print(f"{conf.YELLOW}Exemplos: 192.168.1.0/24, 10.0.0.1-10.0.0.50, 172.16.1.100{conf.RESET}")
            elif PARAMS[idx]["key"] == "delay":
                print(f"{conf.YELLOW}Recomendado: 0.1 a 2.0 segundos{conf.RESET}")
            elif PARAMS[idx]["key"] == "threads":
                print(f"{conf.YELLOW}Recomendado: 20-100 (depende da rede){conf.RESET}")
            elif PARAMS[idx]["key"] == "report_format":
                print(f"{conf.YELLOW}Opções disponíveis: json, xml{conf.RESET}")
            elif PARAMS[idx]["key"] == "verbose":
                print(f"{conf.YELLOW}Opções: true, false{conf.RESET}")
            
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
                elif PARAMS[idx]["key"] == "threads":
                    try:
                        threads = int(new_value)
                        if threads < 1 or threads > 200:
                            print(f"{conf.RED}[!] Threads deve estar entre 1 e 200{conf.RESET}")
                            continue
                    except ValueError:
                        print(f"{conf.RED}[!] Valor inválido para threads. Use números inteiros{conf.RESET}")
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
    """Executa o ping sweep completo"""
    config = {p["key"]: p["value"] for p in PARAMS}
    
    try:
        delay = float(config["delay"])
        threads = int(config["threads"])
        verbose = config["verbose"].lower() == "true"
        
        print(f"\n{conf.PURPLE}{'='*60}{conf.RESET}")
        print(f"{conf.PURPLE}{conf.BOLD} CONFIGURAÇÕES DO PING SWEEP {conf.RESET}")
        print(f"{conf.PURPLE}{'='*60}{conf.RESET}")
        
        print(f"\n{conf.PURPLE}Parâmetros:{conf.RESET}")
        print(f"  Range de IPs: {conf.GREEN}{config['ip_range']}{conf.RESET}")
        print(f"  Delay: {conf.GREEN}{delay}s{conf.RESET}")
        print(f"  Threads: {conf.GREEN}{threads}{conf.RESET}")
        print(f"  Formato: {conf.GREEN}{config['report_format']}{conf.RESET}")
        print(f"  Verbose: {conf.GREEN}{verbose}{conf.RESET}")

        # Executar ping sweep
        scanner = PingSweep(
            ip_range=config["ip_range"],
            delay=delay,
            verbose=verbose,
            max_threads=threads
        )
        
        result = scanner.scan()
        
        if result:
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
            
            print(f"\n{conf.GREEN}[✓] Ping sweep concluído com sucesso!{conf.RESET}")
        else:
            print(f"\n{conf.YELLOW}[!] Scan foi interrompido ou falhou{conf.RESET}")
            
    except Exception as e:
        print(f"{conf.RED}[!] Erro durante execução: {e}{conf.RESET}")

def run_quick_scan():
    """Executa um scan rápido dos primeiros 10 hosts"""
    config = {p["key"]: p["value"] for p in PARAMS}
    
    try:
        delay = float(config["delay"])
        
        scanner = PingSweep(
            ip_range=config["ip_range"],
            delay=delay,
            verbose=True,
            max_threads=10
        )
        
        results = scanner.quick_scan(top_hosts=10)
        
        if results:
            print(f"\n{conf.GREEN}[✓] Hosts ativos encontrados no scan rápido:{conf.RESET}")
            for host in results:
                hostname_info = f" ({host['hostname']})" if host['hostname'] and host['hostname'] != 'Unknown' else ""
                time_info = f" - {host['response_time']:.2f}ms" if host['response_time'] else ""
                print(f"  {conf.GREEN}{host['ip']}{hostname_info}{time_info}{conf.RESET}")
        else:
            print(f"\n{conf.YELLOW}[!] Nenhum host ativo encontrado no scan rápido{conf.RESET}")
            
    except Exception as e:
        print(f"{conf.RED}[!] Erro durante scan rápido: {e}{conf.RESET}")

def command_line_mode():
    parser = argparse.ArgumentParser(description="Ping Sweep - Purple Shiva Tools")
    parser.add_argument("-r", "--range", required=True, help="Range de IPs (ex: 192.168.1.0/24)")
    parser.add_argument("-d", "--delay", type=float, default=0.1, help="Delay entre pings")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Número de threads")
    parser.add_argument("--report", default="json", choices=["json", "xml"], help="Formato do relatório")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo detalhado")
    parser.add_argument("--quick", action="store_true", help="Scan rápido (primeiros 10 hosts)")

    args = parser.parse_args()

    # Atualizar PARAMS com argumentos da linha de comando
    param_map = {
        "ip_range": args.range,
        "delay": str(args.delay),
        "threads": str(args.threads),
        "report_format": args.report,
        "verbose": str(args.verbose).lower()
    }

    # Atualizar PARAMS
    for p in PARAMS:
        if p["key"] in param_map:
            p["value"] = param_map[p["key"]]

    if args.quick:
        run_quick_scan()
    else:
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
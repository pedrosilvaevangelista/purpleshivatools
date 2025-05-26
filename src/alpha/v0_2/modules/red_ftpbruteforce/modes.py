import argparse
import os
from .ftpbruteforce import BruteForceFtp
from .report import WriteJsonLog, WriteXmlLog
from .. import config as conf
from . import help as help_module

baseDir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PARAMS = [
    {"name": "TARGET IP", "key": "ip", "value": "", "desc": "IP do alvo", "required": True},
    {"name": "USERNAME", "key": "username", "value": "", "desc": "Usuário de login", "required": True},
    {"name": "PASSWORD FILE", "key": "passwordFile", "value": "passwords.txt", "desc": "Arquivo com senhas", "required": True},
    {"name": "DELAY", "key": "delay", "value": "0.1", "desc": "Delay entre tentativas", "required": False},
    {"name": "REPORT FORMAT", "key": "reportFormat", "value": "json", "desc": "Formato: json, xml, pdf", "required": False},
]

def print_help():
    try:
        help_module.print_help()
    except Exception as e:
        print(f"{conf.RED}Erro ao mostrar ajuda: {e}{conf.RESET}")

def print_table():
    # Calcula larguras dinamicamente
    col_widths = {
        'num': 4,
        'name': max(len(p['name']) for p in PARAMS) + 2,
        'value': max(len(p['value']) if p['value'] else len('não definido') for p in PARAMS) + 2,
        'desc': max(len(p['desc']) for p in PARAMS) + 2,
        'req': 8  # "OBRIG." ou "OPCL."
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
        # Cores alternadas para melhor legibilidade
        bg_color = conf.RESET if i % 2 == 0 else f"\033[48;2;25;25;35m"
        
        # Prepara valores
        value_raw = p['value'] if p['value'] else 'não definido'
        value_display = f"{conf.GREEN}{value_raw}{conf.RESET}" if p['value'] else f"{conf.YELLOW}{value_raw}{conf.RESET}"
        
        # Status obrigatório/opcional
        status = f"{conf.RED}OBRIG.{conf.RESET}" if p['required'] else f"{conf.BLUE}OPCL. {conf.RESET}"
        
        # Calcula espaçamento correto considerando códigos de cor
        value_padding = col_widths['value'] - len(value_raw) - 1
        status_padding = col_widths['req'] - 6 - 1  # 6 = len("OBRIG.") ou len("OPCL.")
        
        row = f"{bg_color}{conf.PURPLE}|{conf.RESET}{bg_color} {i:<{col_widths['num']-1}}{conf.PURPLE}|{conf.RESET}{bg_color} {p['name']:<{col_widths['name']-1}}{conf.PURPLE}|{conf.RESET}{bg_color} {value_display}{' ' * value_padding}{conf.PURPLE}|{conf.RESET}{bg_color} {p['desc']:<{col_widths['desc']-1}}{conf.PURPLE}|{conf.RESET}{bg_color} {status}{' ' * status_padding}{conf.PURPLE}|{conf.RESET}"
        print(row)
    
    print(separator)

def InteractiveMode():
    print(f"\n{conf.PURPLE}{conf.BOLD}+{'-'*75}+{conf.RESET}")
    print(f"{conf.PURPLE}{conf.BOLD}|{'FTP BRUTEFORCE - PURPLE SHIVA TOOLS':^75}|{conf.RESET}")
    print(f"{conf.PURPLE}{conf.BOLD}+{'-'*75}+{conf.RESET}")

    while True:
        print_table()
        print(f"\n{conf.PURPLE}[?] Digite o número da opção para editar, ou comando:{conf.RESET}")
        print(f"  {conf.GREEN}HELP{conf.RESET}  → Ver instruções")
        print(f"  {conf.GREEN}START{conf.RESET} → Iniciar ataque com os parâmetros atuais")
        print(f"  {conf.RED}QUIT{conf.RESET}  → Sair Da Aplicação\n")

        cmd = input(f"{conf.PURPLE}{conf.BOLD}PurpleShivaTools > {conf.RESET}").strip().upper()
        
        if cmd == "HELP":
            print_help()
        elif cmd == "QUIT":
            break
        elif cmd == "START":
            # Validação rápida antes de iniciar
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
            
            if PARAMS[idx]["key"] == "reportFormat":
                print(f"{conf.YELLOW}Opções disponíveis: json, xml, pdf{conf.RESET}")
            elif PARAMS[idx]["key"] == "delay":
                print(f"{conf.YELLOW}Recomendado: 0.1 a 2.0 segundos{conf.RESET}")
            
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
                elif PARAMS[idx]["key"] == "reportFormat" and new_value.lower() not in ["json", "xml", "pdf"]:
                    print(f"{conf.RED}[!] Formato inválido. Use: json, xml ou pdf{conf.RESET}")
                    continue
                
                PARAMS[idx]["value"] = new_value
                print(f"{conf.GREEN}[✓] Parâmetro atualizado com sucesso!{conf.RESET}")
        else:
            print(f"{conf.RED}[!] Entrada inválida.{conf.RESET}")

def run_attack():
    config = {p["key"]: p["value"] for p in PARAMS}
    delay = float(config["delay"])

    print(f"\n{conf.PURPLE}{'='*60}{conf.RESET}")
    print(f"{conf.PURPLE}{conf.BOLD} INICIANDO ATAQUE FTP BRUTEFORCE {conf.RESET}")
    print(f"{conf.PURPLE}{'='*60}{conf.RESET}")
    
    print(f"\n{conf.PURPLE}Configurações:{conf.RESET}")
    print(f"  Alvo: {conf.GREEN}{config['ip']}{conf.RESET}")
    print(f"  Usuário: {conf.GREEN}{config['username']}{conf.RESET}")
    print(f"  Arquivo de senhas: {conf.GREEN}{config['passwordFile']}{conf.RESET}")
    print(f"  Delay: {conf.GREEN}{delay}s{conf.RESET}")
    print(f"  Formato do relatório: {conf.GREEN}{config['reportFormat']}{conf.RESET}")

    try:
        result = BruteForceFtp(
            ip=config["ip"],
            username=config["username"],
            passwordFile=config["passwordFile"],
            baseDir=baseDir,
            delay=delay
        )

        if not result:
            print(f"{conf.RED}[!] Ataque não retornou resultados.{conf.RESET}")
            return

        fmt = config["reportFormat"]
        outputDir = conf.logDir

        if fmt == "json":
            WriteJsonLog(**result, outputDir=outputDir)
            print(f"{conf.GREEN}[✓] Relatório JSON salvo em {outputDir}{conf.RESET}")
        elif fmt == "xml":
            WriteXmlLog(**result, outputDir=outputDir)
            print(f"{conf.GREEN}[✓] Relatório XML salvo em {outputDir}{conf.RESET}")
        elif fmt == "pdf":
            print(f"{conf.YELLOW}[!] Geração de PDF ainda não implementada.{conf.RESET}")
            
    except Exception as e:
        print(f"{conf.RED}[!] Erro durante execução: {e}{conf.RESET}")

def main():
    parser = argparse.ArgumentParser(description="FTP BruteForce - Purple Shiva Tools")
    parser.add_argument("-i", "--ip", required=True, help="IP do alvo")
    parser.add_argument("-u", "--username", required=True, help="Usuário de login")
    parser.add_argument("-p", "--passwordFile", required=True, help="Arquivo com senhas")
    parser.add_argument("-d", "--delay", type=float, default=0.1, help="Delay entre tentativas")
    parser.add_argument("-r", "--reportFormat", default="json", choices=["json", "xml", "pdf"], help="Formato do relatório")

    args = parser.parse_args()

    # Atualiza PARAMS com argumentos da linha de comando
    for p in PARAMS:
        if hasattr(args, p["key"]):
            p["value"] = str(getattr(args, p["key"]))

    run_attack()

if __name__ == "__main__":
    main()
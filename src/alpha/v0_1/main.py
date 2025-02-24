import os

def main():
    BOLD = "\033[1m"
    PURPLE = "\033[38;2;130;62;176m"
    RED = "\033[38;2;255;0;0m"
    GREEN = "\033[38;2;0;255;0m"
    BLUE = "\033[38;2;0;0;255m"
    RESET = "\033[0m"
    TITLE = r"""
        ____  _   _ ____  ____  _     _____       ____  _   _  _ __     ___   
    |  _ \| | | |  _ \|  _ \| |   | ____|     / ___|| | | || |\ \   / / \      
    | |_) | | | | |_) | |_) | |   |  _|       \___ \| |_| || | \ \ / / _ \
    |  __/| |_| |  _ <|  __/| |___| |___       ___) |  _  || |  \ V / ___ \ 
    |_|   \_____|_| \_\_|   |_____|_____|     |____/|_| |_||_|   \_/_/   \_\ 
                            _________   ___  _    ____           
                        |_   _/ _ \ / _ \| |  / ___|           
                            | || | | | | | | |  \___ \           
                            | || |_| | |_| | |__ __) |           
                            |_| \___/ \___/|____|____/           
                                                                                                                
    """
    print(f"{BOLD}-=-" * 25 + f"{BOLD}{PURPLE}{TITLE}{RESET}" + f"{BOLD}-=-" * 25 + f"\n\n{BOLD}© 2025 - Developed by: {PURPLE}Purple Shiva Team 🔱{RESET}\n" + f"{BOLD}{PURPLE}More info at: <https://github.com/PurpleShivaTeam/purpleshivatools>{RESET}\n" + f"\n{BOLD}This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License.\n<http://www.gnu.org/licenses/>.{RESET}\n\n")

    input("Press any key to continue.")

    module_dir = os.path.join(os.path.dirname(__file__), 'modules')

    print(f"\n{GREEN}---------------| SECURITY UTILITIES |---------------\n{RESET}")
    i = 1
    dictOption = {}
    for filename in os.listdir(module_dir):
        if str(filename).startswith("util"):
            file_path = os.path.join(module_dir, filename)
            with open(file_path, "r") as file:
                tile = file.readline()
                title = file.readline().replace("#", "").strip()
                print(f"{GREEN}[{i}] -> {RESET}{title}")
                dictOption[i] = filename
            i+=1

    # User select the tool to execute
    while True:
        option = input("\nSelect option: ")
        try:
            option = int(option)
            if option >= 1 <= len(dictOption):    
                break
            else:
                print("\nInvalid.")   
        except ValueError:
            print("\nInvalid.")

    # Opens the selected tool
    tool = dictOption[option]
    tool_path = os.path.join(module_dir, tool)
    with open(tool_path, "r") as file:
        code = file.read()
    exec(code)
        

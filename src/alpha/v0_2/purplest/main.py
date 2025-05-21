import os
import sys
import importlib
from modules import config as conf

def run(baseDir=None):
    # === Banner ===
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
    print(f"{conf.BOLD}-=-" * 25 + f"{conf.BOLD}{conf.PURPLE}{TITLE}{conf.RESET}" + f"{conf.BOLD}-=-" * 25)
    print(f"\n{conf.BOLD}© 2025 - Developed by: {conf.PURPLE}Purple Shiva Team 🔱{conf.RESET}")
    print(f"{conf.BOLD}{conf.PURPLE}More info at: <https://github.com/PurpleShivaTeam/purpleshivatools>{conf.RESET}\n")
    print(f"{conf.BOLD}This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License.\n<http://www.gnu.org/licenses/>.{conf.RESET}\n")

    input("Press any key to continue.")

    # === Determine baseDir if not provided ===
    if baseDir is None:
        baseDir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Ensure project root is in sys.path
    if baseDir not in sys.path:
        sys.path.insert(0, baseDir)

    modulesDir = os.path.join(baseDir, "modules")

    categories = {
        "RED TEAM TOOLS": ("red_", conf.RED),
        "BLUE TEAM TOOLS": ("blue_", conf.BLUE),
    }

    dictOption = {}
    optionOndex = 0

    for category, (prefix, color) in categories.items():
        print(f"\n{color}---------------| {category} |---------------{conf.RESET}\n")

        for folderName in sorted(os.listdir(modulesDir)):
            folderPath = os.path.join(modulesDir, folderName)

            if not os.path.isdir(folderPath):
                continue

            if not folderName.startswith(prefix):
                continue

            # Expected tool filename: folder name minus prefix + ".py"
            expectedFileName = folderName[len(prefix):] + ".py"
            expectedFilePath = os.path.join(folderPath, expectedFileName)

            if not os.path.isfile(expectedFilePath):
                continue

            try:
                with open(expectedFilePath, "r", encoding="utf-8") as f:
                    firstLine = f.readline().strip()
                    if firstLine.startswith("#"):
                        title = firstLine.lstrip("#").strip()
                    else:
                        title = expectedFileName[:-3]
            except Exception:
                title = expectedFileName[:-3]

            print(f"{color}[{optionOndex}] -> {conf.RESET}{title}")
            dictOption[optionOndex] = f"modules.{folderName}.{expectedFileName[:-3]}"
            optionOndex += 1

    while True:
        choice = input("\nSelect option: ")
        try:
            choice = int(choice)
            if 0 <= choice < optionOndex:
                break
            else:
                print("Invalid option, try again.")
        except ValueError:
            print("Please enter a number.")

    moduleFullPath = dictOption[choice]

    try:
        # Extract folder from full module path, e.g., "modules.red_sshbruteforce.sshbruteforce"
        toolFolder = moduleFullPath.rsplit(".", 1)[0]
        modesModulePath = f"{toolFolder}.modes"
        modesModule = importlib.import_module(modesModulePath)
    except Exception as e:
        print(f"{conf.RED}Failed to import modes from {toolFolder}: {e}{conf.RESET}")
        sys.exit(1)

    if hasattr(modesModule, "InteractiveMode"):
        try:
            modesModule.InteractiveMode()
        except Exception as e:
            print(f"{conf.RED}Error running InteractiveMode() in {modesModulePath}: {e}{conf.RESET}")
    else:
        print(f"{conf.RED}Module {modesModulePath} has no InteractiveMode() function.{conf.RESET}")


if __name__ == "__main__":
    run()

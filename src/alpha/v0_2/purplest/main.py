#!/usr/bin/env python3
import os
import sys
import importlib
import time
from .help import *

from modules import config as conf
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box
from rich.align import Align
from rich.live import Live

# Version info
VERSION = "0.2"
REPO_URL = "https://github.com/PurpleShivaTeam/purpleshivatools"

console = Console()

def print_progress_rich(count, total, bar_length=40):
    percent = count / total
    filled = int(percent * bar_length)
    bar = "█" * filled + "-" * (bar_length - filled)
    line = Text(f"Loading modules |{bar}| {count}/{total} ({percent:.0%})", style="bold purple")
    return Align.center(line)

def print_logo_centered(logo: str):
    cleaned = "\n".join(line.rstrip() for line in logo.strip("\n").splitlines())
    logo_text = Text(cleaned, style="bold purple")
    console.print(Align.center(logo_text))

def PrintPhrase():
    console.print()
    phrase = Text(conf.GetRandomPhrase(), style="bold purple", justify="center")
    console.print(Align.center(phrase))
    console.print()

def print_banner():
    b = Text(justify="center")
    b.append("Version: ", style="bold cyan"); b.append(f"{VERSION}\n", style="bold green")
    b.append("Repo: ", style="bold cyan");    b.append(f"{REPO_URL}\n", style="bold blue")
    b.append("© 2025 - Developed by: ", style="bold cyan"); b.append("Purple Shiva Team 🔱", style="bold magenta")
    panel = Panel(
        b,
        title="[bold white] Purple Shiva Tools",
        subtitle="[cyan]Red & Blue Team Utilities",
        style="bold white",
        border_style="purple",
        box=box.ROUNDED,
        padding=(1,2)
    )
    console.print(panel)

def get_command(prompt: str, tool_map: dict) -> str:
    """Simplified command input without tab completion"""
    try:
        return input(prompt)
    except EOFError:
        return "exit"  # Handle Ctrl+D gracefully

# Add to main.py (modified version)
PARAMS = [
    {
        "name": "TOOL", 
        "key": "tool",
        "value": "", 
        "desc": "Select tool from the framework", 
        "required": True
    }
]

def print_table():
    # Calculate dynamic widths (even with single parameter)
    col_widths = {
        'num': 4,
        'name': max(len(p['name']) for p in PARAMS) + 2,
        'value': max(len(p['value']) if p['value'] else len('not set') for p in PARAMS) + 2,
        'desc': max(len(p['desc']) for p in PARAMS) + 2,
        'req': 8
    }
    
    # Enforce minimum widths (matches modes.py)
    col_widths['name'] = max(col_widths['name'], 17)
    col_widths['value'] = max(col_widths['value'], 20)
    col_widths['desc'] = max(col_widths['desc'], 30)
    
    # Header
    separator = f"{conf.PURPLE}+{'-' * col_widths['num']}+{'-' * col_widths['name']}+{'-' * col_widths['value']}+{'-' * col_widths['desc']}+{'-' * col_widths['req']}+{conf.RESET}"
    print(f"\n{separator}")
    
    header = f"{conf.PURPLE}|{conf.RESET} {'N°':<{col_widths['num']-1}}{conf.PURPLE}|{conf.RESET} {'OPTION':<{col_widths['name']-1}}{conf.PURPLE}|{conf.RESET} {'VALUE':<{col_widths['value']-1}}{conf.PURPLE}|{conf.RESET} {'DESCRIPTION':<{col_widths['desc']-1}}{conf.PURPLE}|{conf.RESET} {'STATUS':<{col_widths['req']-1}}{conf.PURPLE}|{conf.RESET}"
    print(header)
    print(separator)
    
    # Rows
    for i, p in enumerate(PARAMS):
        value_raw = p['value'] if p['value'] else 'not set'
        value_display = f"{conf.GREEN}{value_raw}{conf.RESET}" if p['value'] else f"{conf.YELLOW}{value_raw}{conf.RESET}"
        status = f"{conf.RED}REQUIRED{conf.RESET}" if p['required'] else f"{conf.BLUE}OPTIONAL{conf.RESET}"
        
        value_padding = col_widths['value'] - len(value_raw) - 1
        status_padding = col_widths['req'] - len("REQUIRED") - 1
        
        row = f"{conf.PURPLE}|{conf.RESET} {i:<{col_widths['num']-1}}{conf.PURPLE}|{conf.RESET} {p['name']:<{col_widths['name']-1}}{conf.PURPLE}|{conf.RESET} {value_display}{' ' * value_padding}{conf.PURPLE}|{conf.RESET} {p['desc']:<{col_widths['desc']-1}}{conf.PURPLE}|{conf.RESET} {status}{' ' * status_padding}{conf.PURPLE}|{conf.RESET}"
        print(row)
    
    print(separator)

def InteractiveMode(tool_map):
    print(f"\n{conf.PURPLE}{conf.BOLD}+{'-'*75}+{conf.RESET}")
    print(f"{conf.PURPLE}{conf.BOLD}|{'PURPLE SHIVA TOOLS - MAIN MENU':^75}|{conf.RESET}")
    print(f"{conf.PURPLE}{conf.BOLD}+{'-'*75}+{conf.RESET}")

    while True:
        print_table()
        print(f"\n{conf.PURPLE}[?] Type option number to edit, or command:{conf.RESET}")
        print(f"  {conf.GREEN}HELP{conf.RESET}   → Show detailed instructions (using for the first time? here is a great place to start!)")
        print(f"  {conf.GREEN}START{conf.RESET}  → Launch selected tool")
        print(f"  {conf.RED}QUIT{conf.RESET}   → Exit framework\n")

        cmd = input(f"{conf.PURPLE}{conf.BOLD}PurpleShell> {conf.RESET}").strip().upper()
        
        if cmd == "HELP":
            print_cli_help()
        elif cmd == "QUIT":
            print(f"{conf.YELLOW}Exiting...{conf.RESET}")
            break
        elif cmd == "START":
            if not PARAMS[0]['value']:
                print(f"{conf.RED}[!] Required parameters not set: SELECTED TOOL{conf.RESET}")
            else:
                launch_tool(PARAMS[0]['value'], tool_map)
        elif cmd == "0":
            print(f"\n{conf.PURPLE}Configuring: {PARAMS[0]['name']}{conf.RESET}")
            print(f"{conf.YELLOW}Description: {PARAMS[0]['desc']}{conf.RESET}")
            print(f"{conf.YELLOW}Available tools: {', '.join(tool_map.keys())}{conf.RESET}")
            
            current_value = PARAMS[0]['value'] if PARAMS[0]['value'] else "not set"
            new_value = input(f"New value for {PARAMS[0]['name']} (current: {current_value}): ").strip()
            
            if new_value:
                if new_value not in tool_map:
                    print(f"{conf.RED}[!] Invalid tool. Available: {', '.join(tool_map.keys())}{conf.RESET}")
                else:
                    PARAMS[0]['value'] = new_value
                    print(f"{conf.GREEN}[✓] Parameter updated successfully!{conf.RESET}")
        else:
            print(f"{conf.RED}[!] Invalid input.{conf.RESET}")

def launch_tool(tool_name, tool_map):
    try:
        module_name = tool_map[tool_name]
        m = importlib.import_module(f"modules.{module_name}.modes")
        m.main()
    except Exception as e:
        print(f"{conf.RED}[!] Failed to launch {tool_name}: {e}{conf.RESET}")

def run(baseDir=None):
    # Initial display
    print_logo_centered(conf.GetRandomLogo())
    PrintPhrase()
    print_banner()
    console.print()
    
    # Set up paths
    if baseDir is None:
        baseDir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if baseDir not in sys.path:
        sys.path.insert(0, baseDir)
    
    # Load modules
    modulesDir = os.path.join(baseDir, "modules")
    categories = {"RED TEAM TOOLS": "red_", "BLUE TEAM TOOLS": "blue_"}
    tools = []
    
    for pref in categories.values():
        for entry in sorted(os.listdir(modulesDir)):
            if entry.startswith(pref):
                td = os.path.join(modulesDir, entry)
                tf = os.path.join(td, entry[len(pref):] + ".py")
                if os.path.isdir(td) and os.path.isfile(tf):
                    tools.append((entry, tf))
    
    total = len(tools)
    loaded, failed = 0, []
    
    # Load modules with progress display
    with Live(console=console, refresh_per_second=12) as live:
        for name, _ in tools:
            try:
                importlib.import_module(f"modules.{name}.{name.split('_',1)[1]}")
            except Exception as e:
                failed.append((name, str(e)))
            finally:
                loaded += 1
                live.update(print_progress_rich(loaded, total))
                time.sleep(0.1)
    
    # Clear the live display completely before continuing
    console.print()
    
    # Show loading results
    if failed:
        err = "\n".join(f"- {n}: {e}" for n,e in failed)
        panel = Panel.fit(Text(f"[!] {len(failed)} failed:\n{err}", style="bold red"), 
                         title="[bold red]Errors", border_style="red")
        console.print(Align.center(panel))
    else:
        panel = Panel.fit(Text(f"[✓] All {total} loaded!", style="bold green"), 
                         title="[bold green]Success", border_style="green")
        console.print(Align.center(panel))
    
    # Create tool map
    tool_map = {e.split('_',1)[1]: e for e,_ in tools}
    prompt = f"{conf.PURPLE}{conf.BOLD}PurpleShell> {conf.RESET}"
    
    InteractiveMode(tool_map) 

if __name__ == "__main__":
    run()
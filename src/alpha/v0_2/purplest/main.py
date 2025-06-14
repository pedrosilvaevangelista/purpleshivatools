#!/usr/bin/env python3
import os
import sys
import importlib
import time

from modules import config as conf
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
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
    
    # Main command loop
    while True:
        try:
            cmd = get_command(prompt, tool_map).strip().lower()
            if not cmd:
                continue
                
            if cmd in ("exit", "quit"):
                print(f"{conf.RED}Exiting...{conf.RESET}")
                break
                
            if cmd == "help":
                print(f"{conf.BOLD}{conf.YELLOW}Available commands:{conf.RESET}")
                print(f"  {conf.GREEN}tools select <tool>{conf.RESET} → Launch tool")
                print(f"  {conf.GREEN}tools print{conf.RESET}           → List tools")
                print(f"  {conf.GREEN}help{conf.RESET}                → Show this message")
                print(f"  {conf.GREEN}exit / quit{conf.RESET}          → Exit")
                continue
                
            if cmd.startswith("tools select "):
                name = cmd[len("tools select "):]
                matches = [n for n in tool_map if n.startswith(name)]
                if len(matches) == 1:
                    try:
                        m = importlib.import_module(f"modules.{tool_map[matches[0]]}.modes")
                        m.main()
                    except Exception as e:
                        print(f"{conf.RED}[!] Failed: {e}{conf.RESET}")
                elif matches:
                    print(f"{conf.YELLOW}[?] Multiple matches:{conf.RESET}")
                    for m in matches:
                        print(f"  - {conf.GREEN}{m}{conf.RESET}")
                else:
                    print(f"{conf.RED}[!] No tool matches '{name}'.{conf.RESET}")
                continue
                
            if cmd == "tools print":
                print(f"\n{conf.BOLD}{conf.CYAN}Available Tools:{conf.RESET}")
                for t in sorted(tool_map): print(f"  - {conf.GREEN}{t}{conf.RESET}")
                print()
                continue
                
            print(f"{conf.RED}[!] Unknown. Type 'help'.{conf.RESET}")
            
        except KeyboardInterrupt:
            print(f"\n{conf.RED}Exiting...{conf.RESET}")
            break

if __name__ == "__main__":
    run()
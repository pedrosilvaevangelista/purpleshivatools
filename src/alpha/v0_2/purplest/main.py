#!/usr/bin/env python3
import os
import sys
import importlib
import time
import msvcrt
import builtins

from modules import config as conf
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.align import Align
from rich.live import Live

# Version info
VERSION = "1.0.0"
REPO_URL = "https://github.com/PurpleShivaTeam/purpleshivatools"

console = Console()

def print_progress_rich(count, total, bar_length=40):
    percent = count / total
    filled = int(percent * bar_length)
    bar = "█"*filled + "-"*(bar_length-filled)
    line = Text(f"Loading modules |{bar}| {count}/{total} ({percent:.0%})", style="bold purple")
    return Align.center(line)

def print_logo_centered(logo: str):
    cleaned = "\n".join(l.rstrip() for l in logo.strip("\n").splitlines())
    console.print(Align.center(Text(cleaned, style="bold purple")))

def PrintPhrase():
    console.print()
    console.print(Align.center(Text(conf.GetRandomPhrase(), style="bold purple")))
    console.print()

def print_banner():
    b = Text(justify="center")
    b.append("Version: ", style="bold cyan"); b.append(f"{VERSION}\n", style="bold green")
    b.append("Repo: ", style="bold cyan");    b.append(f"{REPO_URL}\n", style="bold blue")
    b.append("© 2025 - Developed by: ", style="bold cyan"); b.append("Purple Shiva Team 🔱", style="bold magenta")
    panel = Panel(b,
                  title="[bold white] Purple Shiva Tools",
                  subtitle="[cyan]Red & Blue Team Utilities",
                  style="bold white", border_style="purple", box=box.ROUNDED, padding=(1,2))
    console.print(panel)

def get_command(prompt: str, tool_map: dict) -> str:
    TOP = ["help","tools","exit","quit"]
    SUB = ["select","print"]
    buf = ""
    sys.stdout.write(prompt); sys.stdout.flush()
    while True:
        ch = msvcrt.getwch()
        if ch == "\r":
            print(); return buf
        if ch == "\b":
            if buf: buf = buf[:-1]
            sys.stdout.write("\r"+prompt+buf+" "); sys.stdout.write("\r"+prompt+buf)
            sys.stdout.flush(); continue
        if ch == "\t":
            # tab-complete logic identical to yours...
            stripped = buf.strip(); toks = stripped.split()
            ends = buf.endswith(" ")
            matches=[]
            if not toks:
                matches=TOP
            elif len(toks)==1:
                matches=[c for c in TOP if c.startswith(toks[0])]
            elif toks[0]=="tools":
                if len(toks)==2 and ends and toks[1]=="select":
                    matches=list(tool_map.keys())
                elif len(toks)==2:
                    matches=[s for s in SUB if s.startswith(toks[1])]
                elif len(toks)>=3 and toks[1]=="select":
                    matches=[n for n in tool_map if n.startswith(toks[2])]
            if len(matches)==1:
                last = toks[-1] if not ends else ""
                comp = matches[0][len(last):]
                buf += comp; sys.stdout.write(comp); sys.stdout.flush()
            elif matches:
                print(f"\n{conf.YELLOW}Suggestions:{conf.RESET}")
                for m in matches: print(f"  - {conf.GREEN}{m}{conf.RESET}")
                sys.stdout.write(prompt+buf); sys.stdout.flush()
            continue
        buf += ch; sys.stdout.write(ch); sys.stdout.flush()

def run(baseDir=None):
    print_logo_centered(conf.GetRandomLogo()); PrintPhrase(); print_banner(); console.print()
    if baseDir is None:
        baseDir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if baseDir not in sys.path:
        sys.path.insert(0, baseDir)

    modulesDir = os.path.join(baseDir,"modules")
    categories = {"RED TEAM TOOLS":"red_","BLUE TEAM TOOLS":"blue_"}
    tools=[]
    for pref in categories.values():
        for entry in sorted(os.listdir(modulesDir)):
            if entry.startswith(pref):
                td=os.path.join(modulesDir,entry)
                tf=os.path.join(td,entry[len(pref):]+".py")
                if os.path.isdir(td) and os.path.isfile(tf):
                    tools.append((entry,tf))

    total=len(tools); loaded=0; failed=[]
    with Live(console=console,refresh_per_second=12) as live:
        for name,_ in tools:
            try:
                importlib.import_module(f"modules.{name}.{name.split('_',1)[1]}")
            except Exception as e:
                failed.append((name,str(e)))
            finally:
                loaded+=1
                live.update(print_progress_rich(loaded,total))
                time.sleep(0.1)
    console.print()
    if failed:
        err="\n".join(f"- {n}: {e}" for n,e in failed)
        panel=Panel.fit(Text(f"[!] {len(failed)} failed:\n{err}",style="bold red"),
                       title="[bold red]Errors",border_style="red")
        console.print(Align.center(panel))
    else:
        panel=Panel.fit(Text(f"[✓] All {total} loaded!",style="bold green"),
                       title="[bold green]Success",border_style="green")
        console.print(Align.center(panel))

    tool_map={e.split('_',1)[1]:e for e,_ in tools}
    prompt=f"{conf.PURPLE}{conf.BOLD}PurpleShell> {conf.RESET}"

    while True:
        cmd=get_command(prompt,tool_map).strip().lower()
        if not cmd: continue
        if cmd in ("exit","quit"):
            print(f"{conf.RED}Exiting...{conf.RESET}"); break
        if cmd=="help":
            print(f"{conf.BOLD}{conf.YELLOW}Available commands:{conf.RESET}")
            print(f"  {conf.GREEN}tools select <tool>{conf.RESET} → Launch tool")
            print(f"  {conf.GREEN}tools print{conf.RESET}           → List tools")
            print(f"  {conf.GREEN}help{conf.RESET}                → Show this message")
            print(f"  {conf.GREEN}exit / quit{conf.RESET}          → Exit"); continue

        if cmd.startswith("tools select "):
            name=cmd[len("tools select "):]
            matches=[n for n in tool_map if n.startswith(name)]
            if len(matches)==1:
                # monkey-patch input() via msvcrt-based reader
                orig_input=builtins.input
                def msv_input(prompt_str=""):
                    sys.stdout.write(prompt_str); sys.stdout.flush()
                    buf=""
                    while True:
                        ch=msvcrt.getwch()
                        if ch=="\r":
                            print(); return buf
                        if ch=="\b":
                            if buf: buf=buf[:-1]
                            sys.stdout.write("\b \b"); sys.stdout.flush()
                        else:
                            buf+=ch; sys.stdout.write(ch); sys.stdout.flush()
                builtins.input=msv_input

                try:
                    m=importlib.import_module(f"modules.{tool_map[matches[0]]}.modes")
                    m.main()
                except Exception as e:
                    print(f"{conf.RED}[!] Tool error: {e}{conf.RESET}")
                finally:
                    builtins.input=orig_input

            elif matches:
                print(f"{conf.YELLOW}[?] Multiple matches:{conf.RESET}")
                for m in matches: print(f"  - {conf.GREEN}{m}{conf.RESET}")
            else:
                print(f"{conf.RED}[!] No tool matches '{name}'.{conf.RESET}")
            continue

        if cmd=="tools print":
            print(f"\n{conf.BOLD}{conf.CYAN}Available Tools:{conf.RESET}")
            for t in sorted(tool_map): print(f"  - {conf.GREEN}{t}{conf.RESET}")
            print(); continue

        print(f"{conf.RED}[!] Unknown. Type 'help'.{conf.RESET}")

if __name__=="__main__":
    run()

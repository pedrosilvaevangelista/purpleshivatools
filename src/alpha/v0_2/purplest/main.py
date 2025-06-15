#!/usr/bin/env python3
import os
import sys
import signal
import importlib
import time
import traceback
from contextlib import contextmanager
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

# Global flag para controlar cancelamento
_shutdown_requested = False

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    global _shutdown_requested
    _shutdown_requested = True
    console.print("\n[bold yellow]Interrupt signal received. Gracefully shutting down...[/bold yellow]")
    
    # Se receber outro Ctrl+C, força a saída
    def force_exit(signum, frame):
        console.print("\n[bold red]Force exit requested. Terminating immediately.[/bold red]")
        sys.exit(1)
    
    signal.signal(signal.SIGINT, force_exit)

def setup_signal_handlers():
    """Setup signal handlers for graceful shutdown"""
    signal.signal(signal.SIGINT, signal_handler)
    
    # Handle SIGTERM on Unix-like systems
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)

@contextmanager
def error_handler(operation_name="Operation", show_traceback=False):
    """Context manager for consistent error handling"""
    try:
        yield
    except KeyboardInterrupt:
        console.print(f"\n[bold yellow]⚠️  {operation_name} cancelled by user[/bold yellow]")
        raise
    except ImportError as e:
        console.print(f"[bold red]Import Error in {operation_name}: {str(e)}[/bold red]")
        if show_traceback:
            console.print(f"[dim red]{traceback.format_exc()}[/dim red]")
    except FileNotFoundError as e:
        console.print(f"[bold red]File Not Found in {operation_name}: {str(e)}[/bold red]")
    except PermissionError as e:
        console.print(f"[bold red]Permission Error in {operation_name}: {str(e)}[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Unexpected error in {operation_name}: {str(e)}[/bold red]")
        if show_traceback:
            console.print(f"[dim red]{traceback.format_exc()}[/dim red]")

def check_shutdown():
    """Check if shutdown was requested"""
    if _shutdown_requested:
        console.print("[yellow]Shutdown requested, stopping operation...[/yellow]")
        return True
    return False

def safe_input(prompt: str, timeout: int = None) -> str:
    """Safe input function with cancellation support"""
    try:
        if check_shutdown():
            return "quit"
        return input(prompt)
    except KeyboardInterrupt:
        console.print("\n[yellow]Input cancelled[/yellow]")
        return "quit"
    except EOFError:
        console.print("\n[yellow]EOF received, exiting...[/yellow]")
        return "quit"

def print_progress_rich(count, total, bar_length=40):
    if check_shutdown():
        return Text("Cancelling...", style="bold red")
    
    percent = count / total
    filled = int(percent * bar_length)
    bar = "█" * filled + "-" * (bar_length - filled)
    line = Text(f"Loading modules |{bar}| {count}/{total} ({percent:.0%})", style="bold purple")
    return Align.center(line)

def print_logo_centered(logo: str):
    try:
        cleaned = "\n".join(line.rstrip() for line in logo.strip("\n").splitlines())
        logo_text = Text(cleaned, style="bold purple")
        console.print(Align.center(logo_text))
    except Exception as e:
        console.print(f"[dim red]Error displaying logo: {str(e)}[/dim red]")

def PrintPhrase():
    try:
        console.print()
        phrase = Text(conf.GetRandomPhrase(), style="bold purple", justify="center")
        console.print(Align.center(phrase))
        console.print()
    except Exception as e:
        console.print(f"[dim red]Error displaying phrase: {str(e)}[/dim red]")

def print_banner():
    try:
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
    except Exception as e:
        console.print(f"[bold red]Error displaying banner: {str(e)}[/bold red]")

def get_command(prompt: str, tool_map: dict) -> str:
    """Simplified command input with error handling"""
    return safe_input(prompt)

def get_tool_description(module_path):
    """Extract tool description with error handling"""
    try:
        if not os.path.exists(module_path):
            return "Security Tool (file not found)"
            
        with open(module_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith('#') and not line.startswith('#!/'):
                    description = line[1:].strip()
                    if description:
                        return description
                elif line and not line.startswith('#'):
                    break
    except (IOError, UnicodeDecodeError, PermissionError) as e:
        return f"Security Tool (error reading: {str(e)[:50]})"
    except Exception:
        return "Security Tool (unknown error)"
    
    return "Security Tool"

class ToolManager:
    def __init__(self):
        self.tools = []
        self.selected_tool = None
        self.selected_index = None
    
    def load_tools(self, tool_map, modules_dir):
        """Load tools with comprehensive error handling"""
        self.tools = []
        
        if not os.path.exists(modules_dir):
            console.print(f"[bold red]Modules directory not found: {modules_dir}[/bold red]")
            return
        
        with error_handler("Loading tools"):
            for i, (tool_name, module_name) in enumerate(tool_map.items()):
                if check_shutdown():
                    break
                
                tool_file_path = os.path.join(modules_dir, module_name, f"{tool_name}.py")
                description = get_tool_description(tool_file_path)
                
                category = "RED TEAM" if module_name.startswith("red_") else "BLUE TEAM"
                
                self.tools.append({
                    'index': i,
                    'name': tool_name,
                    'module': module_name,
                    'description': description,
                    'category': category,
                    'selected': False
                })
    
    def select_tool(self, index):
        """Select a tool with validation"""
        try:
            if not 0 <= index < len(self.tools):
                return False
            
            # Deselect all tools first
            for tool in self.tools:
                tool['selected'] = False
            
            # Select the chosen tool
            self.tools[index]['selected'] = True
            self.selected_tool = self.tools[index]['name']
            self.selected_index = index
            return True
        except (IndexError, TypeError):
            return False
    
    def get_selected_tool(self):
        """Get currently selected tool"""
        return self.selected_tool

def print_tools_table(tool_manager):
    """Print tools table with error handling"""
    with error_handler("Displaying tools table"):
        if not tool_manager.tools:
            console.print(f"[bold red][!] No tools loaded[/bold red]")
            return
        
        # Create Rich table with clean styling
        table = Table(
            title="Available Security Tools",
            title_style="bold purple",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold white on purple",
            border_style="purple",
            padding=(0, 1),
            expand=False
        )
        
        # Add columns with proper alignment
        table.add_column("ID", justify="center", style="bold cyan", width=4)
        table.add_column("Tool Name", justify="left", style="bold white", min_width=20)
        table.add_column("Category", justify="center", width=12)
        table.add_column("Description", justify="left", style="dim white", min_width=35)
        table.add_column("Status", justify="center", width=10)
        
        # Add tool rows
        for tool in tool_manager.tools:
            if check_shutdown():
                break
                
            # Format index
            index_str = f"[{tool['index']:02d}]"
            
            # Format tool name
            tool_name = tool['name'].replace('_', ' ').title()
            
            # Format category with appropriate styling
            if tool['category'] == "RED TEAM":
                category_display = "[bold red]RED[/bold red]"
            else:
                category_display = "[bold blue]BLUE[/bold blue]"
            
            # Format description (truncate if too long)
            desc = tool['description']
            if len(desc) > 50:
                desc = desc[:47] + "..."
            
            # Format status and styling based on selection
            if tool['selected']:
                index_display = f"[bold green]{index_str}[/bold green]"
                name_display = f"[bold green]> {tool_name}[/bold green]"
                status_display = "[bold green]SELECTED[/bold green]"
            else:
                index_display = index_str
                name_display = tool_name
                status_display = "[dim]Available[/dim]"
            
            # Add row to table
            table.add_row(
                index_display,
                name_display,
                category_display,
                desc,
                status_display
            )
        
        # Print the table centered
        console.print()
        console.print(Align.center(table))
        console.print()

def InteractiveMode(tool_map, modules_dir):
    """Interactive mode with comprehensive error handling"""
    if check_shutdown():
        return
    
    tool_manager = ToolManager()
    
    with error_handler("Loading tool manager"):
        tool_manager.load_tools(tool_map, modules_dir)
    
    # Main menu header
    with error_handler("Displaying main menu"):
        header_panel = Panel(
            "[bold purple]PURPLE SHIVA TOOLS - MAIN MENU[/bold purple]",
            style="bold white",
            border_style="purple",
            box=box.DOUBLE,
            padding=(1, 2)
        )
        console.print()
        console.print(Align.center(header_panel))

    while not check_shutdown():
        try:
            print_tools_table(tool_manager)
            
            # Show current selection with visual indicator
            selected = tool_manager.get_selected_tool()
            if selected:
                selection_text = Text()
                selection_text.append("Selected Tool: ", style="bold green")
                selection_text.append(selected.upper().replace('_', ' '), style="bold white")
                selection_panel = Panel(
                    selection_text,
                    style="green",
                    border_style="green",
                    box=box.ROUNDED,
                    padding=(0, 1)
                )
                console.print(Align.center(selection_panel))
            else:
                console.print(Align.center(
                    Panel(
                        "[yellow]No tool selected - Choose a tool by entering its ID number[/yellow]",
                        style="yellow",
                        border_style="yellow",
                        box=box.ROUNDED,
                        padding=(0, 1)
                    )
                ))
            
            # Command options
            console.print()
            console.print("[bold purple]Available Commands:[/bold purple]")
            console.print(f"  [cyan]00-{len(tool_manager.tools)-1:02d}[/cyan] → Select tool by ID number")
            console.print(f"  [green]START[/green]   → Launch selected tool")
            console.print(f"  [green]HELP[/green]    → Show detailed instructions")
            console.print(f"  [red]QUIT[/red]    → Exit framework")
            console.print()

            cmd = safe_input(f"{conf.PURPLE}{conf.BOLD}PurpleShell> {conf.RESET}").strip().upper()
            
            if cmd in ["QUIT", "EXIT", "Q"]:
                console.print("[yellow]Exiting Purple Shiva Tools...[/yellow]")
                break
            elif cmd == "HELP":
                with error_handler("Displaying help"):
                    print_cli_help()
            elif cmd == "START":
                selected_tool = tool_manager.get_selected_tool()
                if not selected_tool:
                    console.print("[bold red]No tool selected. Please select a tool first.[/bold red]")
                else:
                    launch_tool(selected_tool, tool_map)
            elif cmd.isdigit():
                try:
                    index = int(cmd)
                    if tool_manager.select_tool(index):
                        tool_name = tool_manager.tools[index]['name']
                        category = tool_manager.tools[index]['category'] 
                        console.print(f"[bold green]Selected: {tool_name.upper().replace('_', ' ')} ({category})[/bold green]")
                    else:
                        console.print(f"[bold red]Invalid tool ID. Please select from 00-{len(tool_manager.tools)-1:02d}[/bold red]")
                except ValueError:
                    console.print(f"[bold red]Invalid number format[/bold red]")
            elif cmd == "":
                continue  # Empty input, just redisplay menu
            else:
                console.print(f"[bold red]Invalid command: '{cmd}'. Enter a tool ID (00-{len(tool_manager.tools)-1:02d}) to select.[/bold red]")
                
        except KeyboardInterrupt:
            console.print("\n[yellow]Returning to main menu...[/yellow]")
            continue
        except Exception as e:
            console.print(f"[bold red]Unexpected error in interactive mode: {str(e)}[/bold red]")
            console.print("[yellow]Continuing...[/yellow]")

def launch_tool(tool_name, tool_map):
    """Launch tool with comprehensive error handling"""
    if check_shutdown():
        return
    
    try:
        module_name = tool_map.get(tool_name)
        if not module_name:
            console.print(f"[bold red]Tool '{tool_name}' not found in tool map[/bold red]")
            return
        
        console.print(f"\n[bold purple]Launching {tool_name.upper().replace('_', ' ')}...[/bold purple]")
        console.print(f"[purple]{'='*60}[/purple]")
        
        with error_handler(f"Tool execution: {tool_name}", show_traceback=True):
            m = importlib.import_module(f"modules.{module_name}.modes")
            if hasattr(m, 'main'):
                m.main()
            else:
                console.print(f"[bold red]No 'main' function found in {module_name}.modes[/bold red]")
        
        if not check_shutdown():
            console.print(f"\n[purple]{'='*60}[/purple]")
            console.print(f"[bold green]{tool_name.upper().replace('_', ' ')} execution completed[/bold green]")
            safe_input(f"{conf.YELLOW}Press Enter to return to main menu...{conf.RESET}")
        
    except KeyboardInterrupt:
        console.print(f"\n[yellow]{tool_name} execution interrupted by user[/yellow]")
    except ImportError as e:
        console.print(f"[bold red]Failed to import module for {tool_name}: {str(e)}[/bold red]")
        console.print("[yellow]Check if the module exists and has correct structure[/yellow]")
    except Exception as e:
        console.print(f"[bold red]Failed to launch {tool_name}: {str(e)}[/bold red]")
        console.print(f"[dim red]Error details: {traceback.format_exc()}[/dim red]")
    finally:
        if not check_shutdown():
            safe_input(f"{conf.YELLOW}Press Enter to return to main menu...{conf.RESET}")

def run(baseDir=None):
    """Main run function with comprehensive error handling"""
    # Setup signal handlers first
    setup_signal_handlers()
    
    try:
        # Initial display
        with error_handler("Displaying startup screen"):
            print_logo_centered(conf.GetRandomLogo())
            PrintPhrase()
            print_banner()
            console.print()
        
        if check_shutdown():
            return
        
        # Set up paths
        if baseDir is None:
            baseDir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if baseDir not in sys.path:
            sys.path.insert(0, baseDir)
        
        # Load modules
        modulesDir = os.path.join(baseDir, "modules")
        
        if not os.path.exists(modulesDir):
            console.print(f"[bold red]Modules directory not found: {modulesDir}[/bold red]")
            return
        
        categories = {"RED TEAM TOOLS": "red_", "BLUE TEAM TOOLS": "blue_"}
        tools = []
        
        with error_handler("Scanning modules directory"):
            for pref in categories.values():
                try:
                    entries = os.listdir(modulesDir)
                except (OSError, PermissionError) as e:
                    console.print(f"[bold red]Cannot access modules directory: {str(e)}[/bold red]")
                    return
                
                for entry in sorted(entries):
                    if check_shutdown():
                        return
                    
                    if entry.startswith(pref):
                        td = os.path.join(modulesDir, entry)
                        tf = os.path.join(td, entry[len(pref):] + ".py")
                        if os.path.isdir(td) and os.path.isfile(tf):
                            tools.append((entry, tf))
        
        if not tools:
            console.print("[bold yellow]No tools found in modules directory[/bold yellow]")
            return
        
        total = len(tools)
        loaded, failed = 0, []
        
        # Load modules with progress display
        try:
            with Live(console=console, refresh_per_second=12) as live:
                for name, _ in tools:
                    if check_shutdown():
                        break
                    
                    try:
                        importlib.import_module(f"modules.{name}.{name.split('_',1)[1]}")
                    except Exception as e:
                        failed.append((name, str(e)))
                    finally:
                        loaded += 1
                        live.update(print_progress_rich(loaded, total))
                        time.sleep(0.1)
        except KeyboardInterrupt:
            console.print("\n[yellow]Module loading interrupted[/yellow]")
        
        if check_shutdown():
            return
        
        # Clear the live display completely before continuing
        console.print()
        
        # Show loading results
        if failed:
            err = "\n".join(f"- {n}: {e[:100]}{'...' if len(e) > 100 else ''}" for n,e in failed)
            panel = Panel.fit(
                Text(f"{len(failed)} modules failed to load:\n{err}", style="bold red"), 
                title="[bold red]Loading Errors", 
                border_style="red"
            )
            console.print(Align.center(panel))
        else:
            panel = Panel.fit(
                Text(f"All {total} modules loaded successfully!", style="bold green"), 
                title="[bold green]Success", 
                border_style="green"
            )
            console.print(Align.center(panel))
        
        # Create tool map
        tool_map = {e.split('_',1)[1]: e for e,_ in tools}
        
        if not tool_map:
            console.print("[bold red]No valid tools found[/bold red]")
            return
        
        # Start interactive mode
        InteractiveMode(tool_map, modulesDir)
        
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Application interrupted by user[/bold yellow]")
    except Exception as e:
        console.print(f"\n[bold red]Fatal error: {str(e)}[/bold red]")
        console.print(f"[dim red]Traceback: {traceback.format_exc()}[/dim red]")
    finally:
        console.print("[bold green]Purple Shiva Tools shutdown complete[/bold green]")

if __name__ == "__main__":
    run()
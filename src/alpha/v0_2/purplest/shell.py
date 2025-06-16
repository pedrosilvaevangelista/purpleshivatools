#!/usr/bin/env python3
import time
import queue
import keyboard
import readline
import os
import sys
from contextlib import contextmanager
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.align import Align
from modules import config as conf
from .help import print_cli_help
from .search import search_tools

console = Console()

class ShellCompleter:
    """Tab completion handler for the shell"""
    
    def __init__(self, tool_manager):
        self.tool_manager = tool_manager
        self.commands = [
            'start', 'search', 'next', 'prev', 'previous', 'help', 'quit', 'exit',
            'clear', 'list', 'info', 'status', 'refresh'
        ]
        # Add tool IDs as completable commands
        self.commands.extend([str(i).zfill(2) for i in range(len(tool_manager.tools))])
        # Add tool names as completable
        self.commands.extend([tool['name'] for tool in tool_manager.tools])
    
    def complete(self, text, state):
        """Handle tab completion"""
        try:
            # Get the current line
            line = readline.get_line_buffer()
            
            # Handle "search " completion with tool names
            if line.lower().startswith('search '):
                search_term = line[7:].lower()
                matches = [tool['name'] for tool in tool_manager.tools 
                          if tool['name'].lower().startswith(search_term)]
                if state < len(matches):
                    return matches[state]
                return None
            
            # Regular command completion
            matches = [cmd for cmd in self.commands if cmd.lower().startswith(text.lower())]
            if state < len(matches):
                return matches[state]
            return None
        except Exception:
            return None

def setup_readline(tool_manager):
    """Setup readline for better input handling"""
    try:
        # Setup history
        histfile = os.path.join(os.path.expanduser("~"), ".purple_shell_history")
        try:
            readline.read_history_file(histfile)
        except FileNotFoundError:
            pass
        
        # Setup completion
        completer = ShellCompleter(tool_manager)
        readline.set_completer(completer.complete)
        readline.parse_and_bind("tab: complete")
        
        # Better editing
        readline.parse_and_bind("set editing-mode emacs")
        readline.parse_and_bind("set completion-ignore-case on")
        readline.parse_and_bind("set show-all-if-ambiguous on")
        
        return histfile
    except ImportError:
        console.print("[yellow]Warning: readline not available, tab completion disabled[/yellow]")
        return None

def save_history(histfile):
    """Save command history"""
    if histfile:
        try:
            readline.set_history_length(1000)
            readline.write_history_file(histfile)
        except Exception:
            pass

def safe_input(prompt: str, use_readline: bool = True) -> str:
    """Safe input function with cancellation support and readline"""
    try:
        if use_readline and 'readline' in sys.modules:
            return input(prompt)
        else:
            return input(prompt)
    except KeyboardInterrupt:
        print()  # New line after ^C
        return ""  # Return empty string instead of "quit"
    except EOFError:
        console.print("\n[yellow]EOF received, exiting...[/yellow]")
        return "quit"

def clear_screen():
    """Clear the screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def launch_tool(tool_name, tool_map):
    """Launch tool with comprehensive error handling"""
    import importlib
    import traceback
    
    try:
        module_name = tool_map.get(tool_name)
        if not module_name:
            console.print(f"[bold red]Tool '{tool_name}' not found in tool map[/bold red]")
            return
        
        console.print(f"\n[bold purple]Launching {tool_name.upper().replace('_', ' ')}...[/bold purple]")
        console.print(f"[purple]{'='*60}[/purple]")
        
        m = importlib.import_module(f"modules.{module_name}.modes")
        if hasattr(m, 'main'):
            m.main()
        else:
            console.print(f"[bold red]No 'main' function found in {module_name}.modes[/bold red]")
        
        console.print(f"\n[purple]{'='*60}[/purple]")
        console.print(f"[bold green]{tool_name.upper().replace('_', ' ')} execution completed[/bold green]")
        safe_input(f"{conf.YELLOW}Press Enter to return to shell...{conf.RESET}")
        
    except KeyboardInterrupt:
        console.print(f"\n[yellow]{tool_name} execution interrupted by user[/yellow]")
    except ImportError as e:
        console.print(f"[bold red]Failed to import module for {tool_name}: {str(e)}[/bold red]")
        console.print("[yellow]Check if the module exists and has correct structure[/yellow]")
    except Exception as e:
        console.print(f"[bold red]Failed to launch {tool_name}: {str(e)}[/bold red]")
        console.print(f"[dim red]Error details: {traceback.format_exc()}[/dim red]")
    finally:
        safe_input(f"{conf.YELLOW}Press Enter to return to shell...{conf.RESET}")

def show_tool_info(tool_manager, tool_id):
    """Show detailed information about a specific tool"""
    try:
        index = int(tool_id)
        if 0 <= index < len(tool_manager.tools):
            tool = tool_manager.tools[index]
            console.print(f"\n[bold purple]Tool Information[/bold purple]")
            console.print(f"[cyan]ID:[/cyan] {index:02d}")
            console.print(f"[cyan]Name:[/cyan] {tool['name'].replace('_', ' ').title()}")
            console.print(f"[cyan]Category:[/cyan] {tool['category']}")
            console.print(f"[cyan]Description:[/cyan] {tool['description']}")
            console.print(f"[cyan]Status:[/cyan] {'SELECTED' if tool['selected'] else 'Available'}")
            console.print()
        else:
            console.print(f"[bold red]Invalid tool ID: {tool_id}[/bold red]")
    except ValueError:
        console.print(f"[bold red]Invalid tool ID format: {tool_id}[/bold red]")

def show_status(tool_manager):
    """Show current shell status"""
    selected = tool_manager.get_selected_tool()
    total_tools = len(tool_manager.tools)
    red_tools = len([t for t in tool_manager.tools if t['category'] == 'RED TEAM'])
    blue_tools = total_tools - red_tools
    
    console.print(f"\n[bold purple]Shell Status[/bold purple]")
    console.print(f"[cyan]Total Tools:[/cyan] {total_tools}")
    console.print(f"[cyan]Red Team Tools:[/cyan] {red_tools}")
    console.print(f"[cyan]Blue Team Tools:[/cyan] {blue_tools}")
    if selected:
        console.print(f"[cyan]Selected Tool:[/cyan] {selected.upper().replace('_', ' ')}")
    else:
        console.print(f"[cyan]Selected Tool:[/cyan] None")
    console.print()

def show_command_hint():
    """Show brief command hint"""
    hint_text = Text()
    hint_text.append("Quick Start: ", style="bold white")
    hint_text.append("Enter tool ", style="dim white")
    hint_text.append("ID", style="bold cyan")
    hint_text.append(" to select • ", style="dim white")
    hint_text.append("start", style="bold green")
    hint_text.append(" to launch • ", style="dim white")
    hint_text.append("help", style="bold yellow")
    hint_text.append(" for commands", style="dim white")
    
    console.print(Align.center(
        Panel(
            hint_text,
            style="dim white",
            border_style="dim white",
            box=box.ROUNDED,
            padding=(0, 1)
        )
    ))
    console.print()

def show_startup_info():
    """Display the startup information - can be called to redisplay after clear"""
    # This function should contain whatever startup information was displayed
    # before the interactive shell started. You'll need to move that code here.
    # For now, I'll create a generic startup display
    
    welcome_text = Text()
    welcome_text.append("🔱 ", style="bold purple")
    welcome_text.append("Interactive Shell Started", style="bold white")
    welcome_text.append(" 🔱", style="bold purple")
    
    console.print(Align.center(
        Panel(
            welcome_text,
            style="bold white",
            border_style="purple",
            box=box.ROUNDED,
            padding=(0, 2)
        )
    ))
    console.print()

def InteractiveMode(tool_manager, tool_map, modules_dir):
    """Enhanced interactive mode with shell-like behavior - preserves startup information"""
    current_page = 1
    per_page = 5
    show_table = True
    first_display = True  # Flag to track if this is the first display
    
    # Setup readline for better input handling
    histfile = setup_readline(tool_manager)
    
    def generate_table():
        """Generate the current page of the tools table"""
        start_idx = (current_page - 1) * per_page
        end_idx = min(start_idx + per_page, len(tool_manager.tools))
        page_tools = tool_manager.tools[start_idx:end_idx]
        total_pages = (len(tool_manager.tools) + per_page - 1) // per_page
        
        table = Table(
            title=f"Available Tools [Page {current_page}/{total_pages}]",
            title_style="bold purple",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold white on purple",
            border_style="purple",
            padding=(0, 1)
        )
        
        table.add_column("ID", justify="center", style="bold cyan", width=4)
        table.add_column("Tool Name", justify="left", style="bold white", min_width=20)
        table.add_column("Category", justify="center", width=12)
        table.add_column("Description", justify="left", style="dim white", min_width=35)
        table.add_column("Status", justify="center", width=10)
        
        for tool in page_tools:
            index_str = f"[{tool['index']:02d}]"
            tool_name = tool['name'].replace('_', ' ').title()
            
            if tool['category'] == "RED TEAM":
                category_display = "[bold red]RED[/bold red]"
            else:
                category_display = "[bold blue]BLUE[/bold blue]"
                
            desc = tool['description']
            if len(desc) > 50: 
                desc = desc[:47] + "..."
            
            if tool['selected']:
                index_display = f"[bold green]{index_str}[/bold green]"
                name_display = f"[bold green]> {tool_name}[/bold green]"
                status_display = "[bold green]SELECTED[/bold green]"
            else:
                index_display = index_str
                name_display = tool_name
                status_display = "[dim]Available[/dim]"
            
            table.add_row(index_display, name_display, category_display, desc, status_display)
        
        return table

    def display_selection():
        """Display the current selection status"""
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
                    "[yellow]No tool selected - Choose a tool by entering its ID or using search[/yellow]",
                    style="yellow",
                    border_style="yellow",
                    box=box.ROUNDED,
                    padding=(0, 1)
            )))

    def refresh_display(force_clear=False, preserve_startup=True):
        """Refresh the complete display with option to preserve startup info"""
        nonlocal first_display
        
        # Only clear screen if explicitly requested or not the first display
        if force_clear or not first_display:
            clear_screen()
            # If we cleared the screen and it's not the first display, 
            # redisplay startup info if requested
            if preserve_startup and not first_display:
                show_startup_info()
        
        console.print(Align.center(generate_table()))
        console.print()
        display_selection()
        console.print()
        show_command_hint()
        
        # After first display, mark it as done
        first_display = False

    def update_table_only():
        """Update only the table without clearing screen or showing other elements"""
        # Move cursor up to overwrite the table
        # This is a simplified approach - in a real implementation you might want
        # to calculate exact lines to move up
        console.print(Align.center(generate_table()))
        console.print()

    def show_help():
        """Show quick help"""
        console.print("[bold purple]Commands:[/bold purple]")
        console.print("  [cyan]<ID>[/cyan]        Select tool by ID (00-99)")
        console.print("  [cyan]start[/cyan]       Launch selected tool")
        console.print("  [cyan]search <term>[/cyan] Search tools")
        console.print("  [cyan]next/prev[/cyan]   Navigate pages")
        console.print("  [cyan]list[/cyan]        Show tools table")
        console.print("  [cyan]info <ID>[/cyan]   Show tool details")
        console.print("  [cyan]status[/cyan]      Show shell status")
        console.print("  [cyan]clear[/cyan]       Clear screen")
        console.print("  [cyan]help[/cyan]        Show this help")
        console.print("  [cyan]quit[/cyan]        Exit")
        console.print("  [dim]Use TAB for completion[/dim]")
        console.print()

    # Display startup info first (this won't be cleared on first display)
    show_startup_info()
    
    # Initial display - this won't clear the screen on first run
    refresh_display()
    
    try:
        # Main shell loop
        while True:
            try:
                cmd = safe_input(f"{conf.PURPLE}PurpleShell> {conf.RESET}").strip()
                
                # Handle empty command (just return to prompt)
                if not cmd:
                    continue
                
                # Parse command and arguments
                parts = cmd.split()
                if not parts:
                    continue
                
                cmd_name = parts[0].lower()
                args = parts[1:] if len(parts) > 1 else []
                
                # Handle quit commands
                if cmd_name in ["quit", "exit", "q"]:
                    console.print("[yellow]Goodbye![/yellow]")
                    break
                
                # Handle clear command - force clear but preserve startup
                elif cmd_name == "clear":
                    refresh_display(force_clear=True, preserve_startup=True)
                
                # Handle list command - force clear but preserve startup
                elif cmd_name == "list":
                    refresh_display(force_clear=True, preserve_startup=True)
                    show_table = True
                
                # Handle help command
                elif cmd_name == "help":
                    if args and args[0] == "full":
                        print_cli_help()
                        safe_input(f"{conf.YELLOW}Press Enter to continue...{conf.RESET}")
                        refresh_display(force_clear=True, preserve_startup=True)
                    else:
                        show_help()
                
                # Handle status command
                elif cmd_name == "status":
                    show_status(tool_manager)
                
                # Handle info command
                elif cmd_name == "info":
                    if args:
                        show_tool_info(tool_manager, args[0])
                    else:
                        console.print("[red]Usage: info <tool_id>[/red]")
                
                # Handle start command
                elif cmd_name == "start":
                    selected_tool = tool_manager.get_selected_tool()
                    if not selected_tool:
                        console.print("[bold red]No tool selected. Use a tool ID to select first.[/bold red]")
                    else:
                        launch_tool(selected_tool, tool_map)
                        # Refresh display after returning from tool
                        refresh_display(force_clear=True, preserve_startup=True)
                
                # Handle search command
                elif cmd_name == "search":
                    if args:
                        search_term = " ".join(args)
                        current_page_ref = [current_page]
                        tool_selected = search_tools(tool_manager, search_term, per_page, current_page_ref)
                        current_page = current_page_ref[0]
                        show_table = True
                        refresh_display(force_clear=True, preserve_startup=True)
                    else:
                        console.print("[red]Usage: search <term>[/red]")
                
                # Handle navigation commands - NOW PRESERVES STARTUP INFO
                elif cmd_name in ["next", "n"]:
                    total_pages = (len(tool_manager.tools) + per_page - 1) // per_page
                    if current_page < total_pages:
                        current_page += 1
                        # Clear screen and redisplay everything including startup info
                        clear_screen()
                        show_startup_info()
                        console.print(Align.center(generate_table()))
                        console.print()
                        display_selection()
                        console.print()
                        show_command_hint()
                        console.print(f"[green]→ Navigated to page {current_page}/{total_pages}[/green]")
                    else:
                        console.print("[red]Already on last page[/red]")
                
                elif cmd_name in ["prev", "p", "previous"]:
                    if current_page > 1:
                        current_page -= 1
                        total_pages = (len(tool_manager.tools) + per_page - 1) // per_page
                        # Clear screen and redisplay everything including startup info
                        clear_screen()
                        show_startup_info()
                        console.print(Align.center(generate_table()))
                        console.print()
                        display_selection()
                        console.print()
                        show_command_hint()
                        console.print(f"[green]← Navigated to page {current_page}/{total_pages}[/green]")
                    else:
                        console.print("[red]Already on first page[/red]")
                
                # Handle tool selection by ID
                elif cmd_name.isdigit():
                    try:
                        index = int(cmd_name)
                        if tool_manager.select_tool(index):
                            tool_name = tool_manager.tools[index]['name']
                            category = tool_manager.tools[index]['category']
                            console.print(f"[bold green]Selected: {tool_name.upper().replace('_', ' ')} ({category})[/bold green]")
                            # Auto-scroll to the page containing the selected tool
                            current_page = (index // per_page) + 1
                            # Update the selection display
                            display_selection()
                        else:
                            console.print(f"[bold red]Invalid tool ID: {cmd_name}[/bold red]")
                    except ValueError:
                        console.print(f"[bold red]Invalid tool ID: {cmd_name}[/bold red]")
                
                # Handle tool selection by name
                elif any(tool['name'] == cmd_name for tool in tool_manager.tools):
                    # Find tool by name
                    for i, tool in enumerate(tool_manager.tools):
                        if tool['name'] == cmd_name:
                            if tool_manager.select_tool(i):
                                console.print(f"[bold green]Selected: {tool['name'].upper().replace('_', ' ')} ({tool['category']})[/bold green]")
                                current_page = (i // per_page) + 1
                                # Update the selection display
                                display_selection()
                            break
                
                # Handle unknown commands
                else:
                    console.print(f"[bold red]Unknown command: {cmd_name}[/bold red]")
                    console.print("[dim]Type 'help' for available commands or use TAB completion[/dim]")
                    
            except KeyboardInterrupt:
                # Handle Ctrl+C gracefully - just show new prompt
                print()  # New line after ^C
                continue
            except Exception as e:
                console.print(f"[bold red]Error: {str(e)}[/bold red]")
                continue
                
    finally:
        # Save command history when exiting
        save_history(histfile)
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
from .manual import print_cli_help
from .search import search_tools

console = Console()

# Update the ShellCompleter class to include new help topics and manual command:
class ShellCompleter:
    """Tab completion handler for the shell"""
    
    def __init__(self, tool_manager):
        self.tool_manager = tool_manager
        self.commands = [
            'start', 'search', 'next', 'prev', 'previous', 'help', 'manual', 'quit', 'exit',
            'clear', 'list', 'info', 'status', 'refresh'
        ]
        # Help topics for completion
        self.help_topics = ['search', 'navigation', 'tools', 'startup', 'manual']
        # Add tool IDs as completable commands
        self.commands.extend([str(i).zfill(2) for i in range(len(tool_manager.tools))])
        # Add tool names as completable
        self.commands.extend([tool['name'] for tool in tool_manager.tools])
    
    def complete(self, text, state):
        """Handle tab completion"""
        try:
            # Get the current line
            line = readline.get_line_buffer()
            
            # Handle "help " completion with topics
            if line.lower().startswith('help '):
                help_term = line[5:].lower()
                matches = [topic for topic in self.help_topics 
                          if topic.lower().startswith(help_term)]
                if state < len(matches):
                    return matches[state]
                return None
            
            # Handle "search " completion with tool names
            elif line.lower().startswith('search '):
                search_term = line[7:].lower()
                matches = [tool['name'] for tool in self.tool_manager.tools 
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

def InteractiveMode(tool_manager, tool_map, modules_dir):
    """Enhanced interactive mode with shell-like behavior - preserves banner by not clearing screen"""
    current_page = 1
    per_page = 5
    
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

    def show_table_and_info():
        """Show the table and related information without clearing screen"""
        console.print(Align.center(generate_table()))
        console.print()
        display_selection()
        console.print()
        show_command_hint()
        

    # Initial display - show table and info without clearing
    show_table_and_info()
    
    try:
        # Main shell loop
        while True:
            try:
                cmd = safe_input(f"{conf.PURPLE}PurpleShell$ {conf.RESET}").strip()
                
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
                
                # Handle clear command - only clear when explicitly requested
                elif cmd_name == "clear":
                    clear_screen()
                    show_table_and_info()
                
                # Handle list command - show table without clearing
                elif cmd_name == "list":
                    show_table_and_info()
                
                # Handle help command (updated section for your shell)
                elif cmd_name == "help":
                    if not args:
                        # Default help - show quick command reference
                        from .manual import print_quick_help
                        print_quick_help()
                    elif args[0] == "manual":
                        # Full manual
                        from .manual import print_manual
                        print_manual()
                        safe_input(f"{conf.YELLOW}Press Enter to return to shell...{conf.RESET}")
                        show_table_and_info()
                    else:
                        # Topic-specific help
                        from .manual import print_topic_help
                        print_topic_help(args[0])

                # Handle manual command (add this new command)
                elif cmd_name == "manual":
                    from .manual import print_manual
                    print_manual()
                    safe_input(f"{conf.YELLOW}Press Enter to return to shell...{conf.RESET}")
                    show_table_and_info()
                
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
                        # Show table again after returning from tool (without clearing screen)
                        console.print("\n[dim]--- Returned to Shell ---[/dim]")
                        show_table_and_info()
                
                # Handle search command
                elif cmd_name == "search":
                    if args:
                        search_term = " ".join(args)
                        current_page_ref = [current_page]
                        
                        # Perform search
                        tool_selected = search_tools(tool_manager, search_term, per_page, current_page_ref)
                        current_page = current_page_ref[0]
                        
                        show_table_and_info()
                    else:
                        console.print("[red]Usage: search <term>[/red]")
                
                # Handle navigation commands - show table instead of updating live
                elif cmd_name in ["next", "n"]:
                    total_pages = (len(tool_manager.tools) + per_page - 1) // per_page
                    if current_page < total_pages:
                        current_page += 1
                        console.print(f"[green]→ Navigating to page {current_page}/{total_pages}[/green]")
                        show_table_and_info()
                    else:
                        console.print("[red]Already on last page[/red]")
                
                elif cmd_name in ["prev", "p", "previous"]:
                    if current_page > 1:
                        current_page -= 1
                        total_pages = (len(tool_manager.tools) + per_page - 1) // per_page
                        console.print(f"[green]← Navigating to page {current_page}/{total_pages}[/green]")
                        show_table_and_info()
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
        # Clean up keyboard hooks and save command history when exiting
        try:
            keyboard.unhook_all()
        except:
            pass
        save_history(histfile)
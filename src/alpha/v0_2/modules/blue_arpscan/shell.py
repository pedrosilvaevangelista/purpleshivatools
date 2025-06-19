#!/usr/bin/env python3
import os
import sys
import readline
import subprocess
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.align import Align
import config as conf
from .arpscan import ArpScan
from .report import write_json_log, write_xml_log

console = Console()

class ArpScanCompleter:
    """Tab completion handler for the ArpScan shell"""
    
    def __init__(self, params):
        self.params = params
        self.commands = [
            'help', 'manual', 'start', 'set', 'show', 'list', 
            'clear', 'status', 'quit', 'exit', 'back'
        ]
        # Add parameter indices for 'set' command
        self.commands.extend([str(i) for i in range(len(params))])
        # Add parameter keys
        self.commands.extend([p['key'] for p in params])
    
    def complete(self, text, state):
        """Handle tab completion"""
        try:
            line = readline.get_line_buffer()
            
            # Handle "set " completion with parameter indices and keys
            if line.lower().startswith('set '):
                set_term = line[4:].lower()
                matches = []
                # Add indices
                matches.extend([str(i) for i in range(len(self.params)) 
                              if str(i).startswith(set_term)])
                # Add parameter keys
                matches.extend([p['key'] for p in self.params 
                              if p['key'].lower().startswith(set_term)])
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

def setup_readline(params):
    """Setup readline for better input handling"""
    try:
        # Setup history
        histfile = os.path.join(os.path.expanduser("~"), ".arpscan_shell_history")
        try:
            readline.read_history_file(histfile)
        except FileNotFoundError:
            pass
        
        # Setup completion
        completer = ArpScanCompleter(params)
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

def safe_input(prompt: str) -> str:
    """Safe input function with cancellation support"""
    try:
        return input(prompt)
    except KeyboardInterrupt:
        print()  # New line after ^C
        return ""
    except EOFError:
        console.print("\n[yellow]EOF received, exiting...[/yellow]")
        return "quit"

def clear_screen():
    """Clear the screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def generate_params_table(params):
    """Generate the parameters configuration table"""
    table = Table(
        title="ARP SCAN - Configuration Parameters",
        title_style="bold purple",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white on purple",
        border_style="purple",
        padding=(0, 1)
    )
    
    table.add_column("ID", justify="center", style="bold cyan", width=4)
    table.add_column("Parameter", justify="left", style="bold white", min_width=15)
    table.add_column("Current Value", justify="left", min_width=20)
    table.add_column("Description", justify="left", style="dim white", min_width=25)
    table.add_column("Required", justify="center", width=10)
    
    for i, param in enumerate(params):
        param_id = f"[{i}]"
        param_name = param['name']
        
        # Format current value with colors
        if param['value']:
            current_value = f"[bold green]{param['value']}[/bold green]"
        else:
            current_value = f"[yellow]not set[/yellow]"
        
        description = param['desc']
        if len(description) > 40:
            description = description[:37] + "..."
        
        required_status = "[bold red]YES[/bold red]" if param['required'] else "[dim]NO[/dim]"
        
        table.add_row(param_id, param_name, current_value, description, required_status)
    
    return table

def show_status(params):
    """Show current configuration status"""
    required_set = sum(1 for p in params if p['required'] and p['value'])
    required_total = sum(1 for p in params if p['required'])
    optional_set = sum(1 for p in params if not p['required'] and p['value'])
    optional_total = sum(1 for p in params if not p['required'])
    
    status_text = Text()
    status_text.append("Configuration Status: ", style="bold white")
    
    if required_set == required_total:
        status_text.append("READY", style="bold green")
    else:
        status_text.append("INCOMPLETE", style="bold red")
    
    status_text.append(f" • Required: {required_set}/{required_total}", style="cyan")
    status_text.append(f" • Optional: {optional_set}/{optional_total}", style="dim cyan")
    
    # Center the status panel
    console.print(Align.center(
        Panel(
            status_text,
            style="white",
            border_style="purple",
            box=box.ROUNDED,
            padding=(0, 1)
        )
    ))
def show_quick_help():
    """Show professional command reference using table format"""
    # Define color scheme matching base shell
    HEADER_COLOR = "bold bright_blue"
    BORDER_COLOR = "bright_white"
    ACCENT_COLOR = "cyan"
    BODY_COLOR = "white"
    
    console.print(f"\n[{HEADER_COLOR}]ArpScan Shell Commands[/]")
    
    # Create command table
    table = Table(
        show_header=True,
        header_style=HEADER_COLOR,
        border_style=BORDER_COLOR,
        box=box.ROUNDED,
        padding=(0, 1)
    )
    
    table.add_column("Command", style=ACCENT_COLOR, min_width=12)
    table.add_column("Description", style=BODY_COLOR, min_width=40)
    table.add_column("Example", style="dim " + BODY_COLOR, min_width=25)
    
    # Configuration commands
    table.add_row("set", "Set parameter value by ID or key", "set 0 192.168.1.0/24")
    table.add_row("show/list", "Show current configuration parameters", "show")
    table.add_row("status", "Show configuration completeness status", "status")
    
    # Execution commands
    table.add_row("start", "Start ArpScan with current config", "start")
    
    # Navigation commands
    table.add_row("help", "Show this command reference", "help")
    table.add_row("manual", "Show detailed documentation", "manual")
    table.add_row("clear", "Clear screen", "clear")
    table.add_row("quit/exit/back", "Return to main menu", "exit")
    
    console.print(table)
    
    # Professional tips
    console.print(f"\n[{ACCENT_COLOR}]Tips:[/] Use TAB for autocompletion. Type 'manual' for complete documentation.")
    console.print(f"      Parameters can be set by ID (number) or key (name).")
    console.print(f"      Required parameters: [bold red]IP Range[/]\n")

def show_manual():
    from .manual import print_arpscan_manual
    print_arpscan_manual()

def set_parameter_interactive(params, param_identifier):
    """Set parameter value interactively by ID or key"""
    param_index = None
    
    # Try to find by index first
    if param_identifier.isdigit():
        index = int(param_identifier)
        if 0 <= index < len(params):
            param_index = index
    
    # Try to find by key
    if param_index is None:
        for i, param in enumerate(params):
            if param['key'] == param_identifier:
                param_index = i
                break
    
    if param_index is None:
        console.print(f"[bold red]Parameter '{param_identifier}' not found[/bold red]")
        return False
    
    param = params[param_index]
    
    # Prompt for value
    value = safe_input(f"Enter value for {param['name']}: ").strip()
    if not value:
        console.print("[yellow]No value entered. Setting canceled.[/yellow]")
        return False
    
    # Validate the value based on parameter type
    if param['key'] == 'delay':
        try:
            float(value)
        except ValueError:
            console.print(f"[bold red]Invalid delay value. Use numbers (e.g., 0.1)[/bold red]")
            return False
    elif param['key'] == 'timeout':
        try:
            float(value)
        except ValueError:
            console.print(f"[bold red]Invalid timeout value. Use numbers (e.g., 2)[/bold red]")
            return False
    elif param['key'] == 'report_format':
        if value.lower() not in ['json', 'xml']:
            console.print(f"[bold red]Invalid format. Use: json or xml[/bold red]")
            return False
        value = value.lower()
    elif param['key'] == 'verbose':
        if value.lower() not in ['true', 'false']:
            console.print(f"[bold red]Invalid verbose value. Use: true or false[/bold red]")
            return False
        value = value.lower()
    
    # Set the value
    params[param_index]['value'] = value
    console.print(f"[bold green]✓ Set {param['name']} = {value}[/bold green]")
    return True

def validate_config(params):
    """Validate current configuration"""
    missing_required = []
    for param in params:
        if param['required'] and not param['value']:
            missing_required.append(param['name'])
    
    return len(missing_required) == 0, missing_required

def run_arpscan(params):
    """Execute ArpScan with current configuration"""
    is_valid, missing = validate_config(params)
    
    if not is_valid:
        console.print(f"[bold red]Cannot start: Missing required parameters: {', '.join(missing)}[/bold red]")
        return
    
    # Convert params to config dict
    config = {p['key']: p['value'] for p in params}
    
    try:
        delay = float(config['delay'])
        timeout = float(config['timeout'])
        verbose = config['verbose'].lower() == 'true'
        
        console.print(f"\n[purple]{'='*60}[/purple]")
        console.print(f"[bold purple] STARTING ARPSCAN [/bold purple]")
        console.print(f"[purple]{'='*60}[/purple]")
        
        console.print(f"\n[bold]Configuration:[/bold]")
        console.print(f"  Range: [green]{config['ip_range']}[/green]")
        console.print(f"  Delay: [green]{delay}s[/green]")
        console.print(f"  Timeout: [green]{timeout}s[/green]")
        console.print(f"  Format: [green]{config['report_format']}[/green]")
        console.print(f"  Verbose: [green]{verbose}[/green]")
        
        # Execute scan
        scanner = ArpScan(
            ip_range=config['ip_range'],
            delay=delay,
            timeout=timeout,
            verbose=verbose
        )
        
        result = scanner.scan()
        
        # Generate report
        fmt = config['report_format'].lower()
        if fmt == 'json':
            write_json_log(
                ip_range=result['ip_range'],
                total_ips=result['total_ips'],
                alive_hosts=result['alive_hosts'],
                duration=result['duration']
            )
        elif fmt == 'xml':
            write_xml_log(
                ip_range=result['ip_range'],
                total_ips=result['total_ips'],
                alive_hosts=result['alive_hosts'],
                duration=result['duration']
            )
        
        console.print(f"\n[bold green]✓ Scan completed successfully![/bold green]")
        console.print(f"[green]Results saved in {fmt.upper()} format[/green]")
        
    except Exception as e:
        console.print(f"[bold red]✗ Scan failed: {str(e)}[/bold red]")

def ArpScanShell(params):
    """Main ArpScan shell interface"""
    # Setup readline
    histfile = setup_readline(params)
    
    def find_parameter(param_identifier):
        """Find parameter by ID or key"""
        # Try to find by index first
        if param_identifier.isdigit():
            index = int(param_identifier)
            if 0 <= index < len(params):
                return params[index]
        
        # Try to find by key
        for param in params:
            if param['key'] == param_identifier:
                return param
        
        return None
    
    def set_parameter_interactive(param_identifier):
        """Set parameter value interactively by ID or key"""
        param = find_parameter(param_identifier)
        if not param:
            console.print(f"[bold red]Parameter '{param_identifier}' not found[/bold red]")
            return False
        
        # Prompt for value
        value = safe_input(f"Enter value for {param['name']}: ").strip()
        if not value:
            console.print("[yellow]No value entered. Setting canceled.[/yellow]")
            return False
        
        # Validate the value based on parameter type
        if param['key'] == 'delay':
            try:
                float(value)
            except ValueError:
                console.print(f"[bold red]Invalid delay value. Use numbers (e.g., 0.1)[/bold red]")
                return False
        elif param['key'] == 'timeout':
            try:
                float(value)
            except ValueError:
                console.print(f"[bold red]Invalid timeout value. Use numbers (e.g., 2)[/bold red]")
                return False
        elif param['key'] == 'report_format':
            if value.lower() not in ['json', 'xml']:
                console.print(f"[bold red]Invalid format. Use: json or xml[/bold red]")
                return False
            value = value.lower()
        elif param['key'] == 'verbose':
            if value.lower() not in ['true', 'false']:
                console.print(f"[bold red]Invalid verbose value. Use: true or false[/bold red]")
                return False
            value = value.lower()
        
        # Set the value
        param['value'] = value
        console.print(f"[bold green]✓ Set {param['name']} = {value}[/bold green]")
        return True

    def show_interface():
        """Show the main interface"""
        # Center the table like in base shell
        console.print(Align.center(generate_params_table(params)))
        console.print()
        show_status(params)
        console.print()
    
    # Initial display
    show_interface()
    
    try:
        while True:
            try:
                cmd = safe_input(f"{conf.PURPLE}PurpleShell(arpscan)$ {conf.RESET}").strip()
                
                if not cmd:
                    continue
                
                parts = cmd.split()
                cmd_name = parts[0].lower()
                args = parts[1:] if len(parts) > 1 else []
                
                # Handle quit commands
                if cmd_name in ['quit', 'exit', 'back', 'q']:
                    console.print("[yellow]Returning to main menu...[/yellow]")
                    break
                
                # Handle clear command
                elif cmd_name == 'clear':
                    clear_screen()
                    show_interface()
                
                # Handle show/list commands
                elif cmd_name in ['show', 'list']:
                    show_interface()
                
                # Handle status command
                elif cmd_name == 'status':
                    show_status(params)
                
                # Handle help command
                elif cmd_name == 'help':
                    show_quick_help()
                
                # Handle manual command
                elif cmd_name == 'manual':
                    show_manual()
                    safe_input(f"{conf.YELLOW}Press Enter to continue...{conf.RESET}")
                    show_interface()
                
                # Handle set command - now interactive
                elif cmd_name == 'set':
                    if not args:
                        console.print("[red]Usage: set <parameter_id|key>[/red]")
                        console.print("[dim]Example: set 0 or set ip_range[/dim]")
                    else:
                        param_id = args[0]
                        if set_parameter_interactive(param_id):
                            show_status(params)
                
                # Handle start command
                elif cmd_name == 'start':
                    run_arpscan(params)
                    safe_input(f"{conf.YELLOW}Press Enter to continue...{conf.RESET}")
                    show_interface()
                
                # Handle unknown commands
                else:
                    console.print(f"[bold red]Unknown command: {cmd_name}[/bold red]")
                    console.print("[dim]Type 'help' for available commands or use TAB completion[/dim]")
                    
            except KeyboardInterrupt:
                print()  # New line after ^C
                continue
            except Exception as e:
                console.print(f"[bold red]Error: {str(e)}[/bold red]")
                continue
                
    finally:
        save_history(histfile)
        # Return to main menu
        try:
            bootstrap_path = conf.HomeDir
            if os.path.exists(bootstrap_path):
                console.print(f"\n[green][+] Redirecting to main menu...[/green]")
                subprocess.run(["python3", bootstrap_path])
        except Exception as e:
            console.print(f"[red]Error returning to main menu: {e}[/red]")
    """Main ArpScan shell interface"""
    # Setup readline
    histfile = setup_readline(params)
    
    def show_interface():
        """Show the main interface"""
        # Center the table like in base shell
        console.print(Align.center(generate_params_table(params)))
        console.print()
        show_status(params)
        console.print()
    
    # Initial display
    show_interface()
    
    try:
        while True:
            try:
                cmd = safe_input(f"{conf.PURPLE}PurpleShell(arpscan)$ {conf.RESET}").strip()
                
                if not cmd:
                    continue
                
                parts = cmd.split()
                cmd_name = parts[0].lower()
                args = parts[1:] if len(parts) > 1 else []
                
                # Handle quit commands
                if cmd_name in ['quit', 'exit', 'back', 'q']:
                    console.print("[yellow]Returning to main menu...[/yellow]")
                    break
                
                # Handle clear command
                elif cmd_name == 'clear':
                    clear_screen()
                    show_interface()
                
                # Handle show/list commands
                elif cmd_name in ['show', 'list']:
                    show_interface()
                
                # Handle status command
                elif cmd_name == 'status':
                    show_status(params)
                
                # Handle help command
                elif cmd_name == 'help':
                    show_quick_help()
                
                # Handle manual command
                elif cmd_name == 'manual':
                    show_manual()
                    safe_input(f"{conf.YELLOW}Press Enter to continue...{conf.RESET}")
                    show_interface()
                
                # Handle set command
                elif cmd_name == 'set':
                    if len(args) < 2:
                        console.print("[red]Usage: set <parameter_id|key> <value>[/red]")
                        console.print("[dim]Example: set 0 192.168.1.0/24 or set ip_range 192.168.1.0/24[/dim]")
                    else:
                        param_id = args[0]
                        value = " ".join(args[1:])  # Support values with spaces
                        if set_parameter(params, param_id, value):
                            show_status(params)
                
                # Handle start command (removed run command)
                elif cmd_name == 'start':
                    run_arpscan(params)
                    safe_input(f"{conf.YELLOW}Press Enter to continue...{conf.RESET}")
                    show_interface()
                
                # Handle unknown commands
                else:
                    console.print(f"[bold red]Unknown command: {cmd_name}[/bold red]")
                    console.print("[dim]Type 'help' for available commands or use TAB completion[/dim]")
                    
            except KeyboardInterrupt:
                print()  # New line after ^C
                continue
            except Exception as e:
                console.print(f"[bold red]Error: {str(e)}[/bold red]")
                continue
                
    finally:
        save_history(histfile)
        # Return to main menu
        try:
            bootstrap_path = conf.HomeDir
            if os.path.exists(bootstrap_path):
                console.print(f"\n[green][+] Redirecting to main menu...[/green]")
                subprocess.run(["python3", bootstrap_path])
        except Exception as e:
            console.print(f"[red]Error returning to main menu: {e}[/red]")
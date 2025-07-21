from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.box import ROUNDED

console = Console()

def print_arpscan_manual():
    # Define color scheme matching base shell
    HEADER_COLOR = "bold bright_blue"
    BORDER_COLOR = "bright_white"
    ACCENT_COLOR = "cyan"
    BODY_COLOR = "white"
    
    # Main banner
    console.print(Panel.fit(
        "[bold magenta]ArpScan - Network Discovery Tool[/bold magenta]",
        subtitle="[bold yellow]Purple Shiva Tools[/bold yellow]",
        style="magenta",
        box=ROUNDED
    ))
    
    # Interactive Shell Section
    interactive_text = Text.assemble(
        ("Interactive Shell Usage\n\n", HEADER_COLOR),
        ("The ArpScan shell provides an intuitive interface for configuring and "
         "executing network scans:\n\n", BODY_COLOR),
        ("Configuration Workflow:\n", ACCENT_COLOR),
        ("  1. View current parameters with 'show' or 'list'\n", BODY_COLOR),
        ("  2. Initiate setting a value with 'set <ID|key>'\n", BODY_COLOR),
        ("  3. Enter the value when prompted\n", BODY_COLOR),
        ("  4. Check configuration status with 'status'\n", BODY_COLOR),
        ("  5. Execute scan with 'start'\n\n", BODY_COLOR),
        ("Key Features:\n", ACCENT_COLOR),
        ("  - Tab completion for commands and parameters\n", BODY_COLOR),
        ("  - Interactive prompts for parameter values\n", BODY_COLOR),
        ("  - Real-time validation of input values\n", BODY_COLOR),
        ("  - Detailed error messages for misconfigurations\n", BODY_COLOR),
        ("  - Automatic report generation in JSON/XML format", BODY_COLOR)
    )
    
    console.print(Panel(
        interactive_text,
        title=f"[{HEADER_COLOR}]INTERACTIVE SHELL[/]",
        border_style=BORDER_COLOR,
        box=ROUNDED
    ))
    
    # Parameters Table
    param_table = Table(
        title=f"[{HEADER_COLOR}]Configuration Parameters[/]",
        box=ROUNDED,
        header_style=HEADER_COLOR,
        border_style=BORDER_COLOR
    )
    param_table.add_column("ID", style=ACCENT_COLOR, justify="center")
    param_table.add_column("Parameter", style=ACCENT_COLOR)
    param_table.add_column("Description", style=BODY_COLOR)
    param_table.add_column("Required", justify="center")
    
    param_table.add_row("0", "IP Range", "Target IPs (CIDR, range, or single IP)", "[bold red]✓[/bold red]")
    param_table.add_row("1", "Delay", "Time between scan attempts (seconds)", "")
    param_table.add_row("2", "Timeout", "Response timeout per host (seconds)", "")
    param_table.add_row("3", "Report Format", "Output format (json/xml)", "")
    param_table.add_row("4", "Verbose", "Detailed output mode (true/false)", "")
    
    console.print(param_table)
    console.print()
    
    # Command Reference
    cmd_table = Table(
        title=f"[{HEADER_COLOR}]Shell Commands[/]",
        box=ROUNDED,
        header_style=HEADER_COLOR,
        border_style=BORDER_COLOR
    )
    cmd_table.add_column("Command", style=ACCENT_COLOR)
    cmd_table.add_column("Description", style=BODY_COLOR)
    cmd_table.add_column("Example", style="dim " + BODY_COLOR)
    
    cmd_table.add_row("set", "Configure parameter value interactively", "set 0")
    cmd_table.add_row("show/list", "Display current configuration", "show")
    cmd_table.add_row("status", "Show configuration status", "status")
    cmd_table.add_row("start", "Execute ARP scan", "start")
    cmd_table.add_row("help", "Show command reference", "help")
    cmd_table.add_row("manual", "Display this manual", "manual")
    cmd_table.add_row("clear", "Clear terminal screen", "clear")
    cmd_table.add_row("quit/exit/back", "Return to main menu", "exit")
    
    console.print(cmd_table)
    console.print()
    
    # Usage Examples
    examples_text = Text.assemble(
        ("Common Usage Examples\n\n", HEADER_COLOR),
        ("Scan Local Network:\n", ACCENT_COLOR),
        ("  $ set 0\n", BODY_COLOR),
        ("  Enter value for IP Range: 192.168.1.0/24\n", BODY_COLOR),
        ("  $ set 1\n", BODY_COLOR),
        ("  Enter value for Delay: 0.2\n", BODY_COLOR),
        ("  $ start\n\n", BODY_COLOR),
        
        ("Fast Scan with XML Output:\n", ACCENT_COLOR),
        ("  $ set ip_range\n", BODY_COLOR),
        ("  Enter value for IP Range: 10.0.0.1-10.0.0.50\n", BODY_COLOR),
        ("  $ set delay\n", BODY_COLOR),
        ("  Enter value for Delay: 0.05\n", BODY_COLOR),
        ("  $ set report_format\n", BODY_COLOR),
        ("  Enter value for Report Format: xml\n", BODY_COLOR),
        ("  $ start\n\n", BODY_COLOR),
        
        ("Detailed Scan with Verbose Output:\n", ACCENT_COLOR),
        ("  $ set 0\n", BODY_COLOR),
        ("  Enter value for IP Range: 172.16.32.5\n", BODY_COLOR),
        ("  $ set timeout\n", BODY_COLOR),
        ("  Enter value for Timeout: 3\n", BODY_COLOR),
        ("  $ set verbose\n", BODY_COLOR),
        ("  Enter value for Verbose: true\n", BODY_COLOR),
        ("  $ start", BODY_COLOR)
    )
    
    console.print(Panel(
        examples_text,
        title=f"[{HEADER_COLOR}]USAGE EXAMPLES[/]",
        border_style=BORDER_COLOR,
        box=ROUNDED
    ))
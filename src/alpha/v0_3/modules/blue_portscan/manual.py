from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.box import ROUNDED

console = Console()

def print_portscan_manual():
    # Define color scheme matching base shell
    HEADER_COLOR = "bold bright_blue"
    BORDER_COLOR = "bright_white"
    ACCENT_COLOR = "cyan"
    BODY_COLOR = "white"
    
    # Main banner
    console.print(Panel.fit(
        "[bold magenta]PortScan - Network Port Discovery Tool[/bold magenta]",
        subtitle="[bold yellow]Purple Shiva Tools[/bold yellow]",
        style="magenta",
        box=ROUNDED
    ))
    
    # Interactive Shell Section
    interactive_text = Text.assemble(
        ("Interactive Shell Usage\n\n", HEADER_COLOR),
        ("The PortScan shell provides an intuitive interface for configuring and "
         "executing port scanning operations:\n\n", BODY_COLOR),
        ("Configuration Workflow:\n", ACCENT_COLOR),
        ("  1. View current parameters with 'show' or 'list'\n", BODY_COLOR),
        ("  2. Set parameter values with 'set <ID|key> <value>'\n", BODY_COLOR),
        ("  3. Check configuration status with 'status'\n", BODY_COLOR),
        ("  4. Execute scan with 'start'\n\n", BODY_COLOR),
        ("Key Features:\n", ACCENT_COLOR),
        ("  - Tab completion for commands and parameters\n", BODY_COLOR),
        ("  - Direct parameter setting with validation\n", BODY_COLOR),
        ("  - Real-time configuration status monitoring\n", BODY_COLOR),
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
    
    param_table.add_row("0", "Target IP", "Target host IP address or hostname", "[bold red]✓[/bold red]")
    param_table.add_row("1", "Port Range", "Port range to scan (e.g., 1-1000, 80,443)", "[bold red]✓[/bold red]")
    param_table.add_row("2", "Delay", "Time between port scans (seconds)", "")
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
    
    cmd_table.add_row("set", "Configure parameter value directly", "set 0 192.168.1.1")
    cmd_table.add_row("show/list", "Display current configuration", "show")
    cmd_table.add_row("status", "Show configuration status", "status")
    cmd_table.add_row("start", "Execute port scan", "start")
    cmd_table.add_row("help", "Show command reference", "help")
    cmd_table.add_row("manual", "Display this manual", "manual")
    cmd_table.add_row("clear", "Clear terminal screen", "clear")
    cmd_table.add_row("quit/exit/back", "Return to main menu", "exit")
    
    console.print(cmd_table)
    console.print()
    
    # Port Range Examples
    port_examples_text = Text.assemble(
        ("Port Range Syntax\n\n", HEADER_COLOR),
        ("Single Port:\n", ACCENT_COLOR),
        ("  80, 443, 22\n\n", BODY_COLOR),
        
        ("Port Range:\n", ACCENT_COLOR),
        ("  1-1000, 20-30, 8000-9000\n\n", BODY_COLOR),
        
        ("Multiple Ports/Ranges:\n", ACCENT_COLOR),
        ("  80,443,8080, 20-25,80,443\n\n", BODY_COLOR),
        
        ("Common Port Sets:\n", ACCENT_COLOR),
        ("  • Web Services: 80,443,8080,8443\n", BODY_COLOR),
        ("  • File Transfer: 20,21,22,69,989,990\n", BODY_COLOR),
        ("  • Mail Services: 25,110,143,993,995\n", BODY_COLOR),
        ("  • Database: 1433,1521,3306,5432,27017\n", BODY_COLOR),
        ("  • Remote Access: 22,23,3389,5900,5901", BODY_COLOR)
    )
    
    console.print(Panel(
        port_examples_text,
        title=f"[{HEADER_COLOR}]PORT RANGE EXAMPLES[/]",
        border_style=BORDER_COLOR,
        box=ROUNDED
    ))
    
    # Usage Examples
    examples_text = Text.assemble(
        ("Common Usage Examples\n\n", HEADER_COLOR),
        ("Basic Web Server Scan:\n", ACCENT_COLOR),
        ("  $ set 0 192.168.1.100\n", BODY_COLOR),
        ("  $ set 1 80,443,8080,8443\n", BODY_COLOR),
        ("  $ set 3 json\n", BODY_COLOR),
        ("  $ start\n\n", BODY_COLOR),
        
        ("Fast Network Range Scan:\n", ACCENT_COLOR),
        ("  $ set ip 10.0.0.1\n", BODY_COLOR),
        ("  $ set port_range 1-1000\n", BODY_COLOR),
        ("  $ set delay 0.01\n", BODY_COLOR),
        ("  $ set report_format xml\n", BODY_COLOR),
        ("  $ start\n\n", BODY_COLOR),
        
        ("Detailed Service Discovery:\n", ACCENT_COLOR),
        ("  $ set 0 target.example.com\n", BODY_COLOR),
        ("  $ set 1 20-25,53,80,110,143,443,993,995\n", BODY_COLOR),
        ("  $ set 2 0.1\n", BODY_COLOR),
        ("  $ set 4 true\n", BODY_COLOR),
        ("  $ start\n\n", BODY_COLOR),
        
        ("Stealth Scan (Slow):\n", ACCENT_COLOR),
        ("  $ set ip 172.16.1.50\n", BODY_COLOR),
        ("  $ set port_range 1-65535\n", BODY_COLOR),
        ("  $ set delay 1.0\n", BODY_COLOR),
        ("  $ set verbose true\n", BODY_COLOR),
        ("  $ start", BODY_COLOR)
    )
    
    console.print(Panel(
        examples_text,
        title=f"[{HEADER_COLOR}]USAGE EXAMPLES[/]",
        border_style=BORDER_COLOR,
        box=ROUNDED
    ))
    
    # Tips and Best Practices
    tips_text = Text.assemble(
        ("Performance & Security Tips\n\n", HEADER_COLOR),
        ("Performance Optimization:\n", ACCENT_COLOR),
        ("  • Use smaller port ranges for faster scans\n", BODY_COLOR),
        ("  • Adjust delay based on network conditions\n", BODY_COLOR),
        ("  • Lower delays (0.01-0.1s) for internal networks\n", BODY_COLOR),
        ("  • Higher delays (0.5-2s) for external/remote hosts\n\n", BODY_COLOR),
        
        ("Security Considerations:\n", ACCENT_COLOR),
        ("  • Port scanning may trigger security alerts\n", BODY_COLOR),
        ("  • Always obtain proper authorization\n", BODY_COLOR),
        ("  • Use stealth timing for sensitive environments\n", BODY_COLOR),
        ("  • Monitor logs for scan detection\n\n", BODY_COLOR),
        
        ("Troubleshooting:\n", ACCENT_COLOR),
        ("  • Enable verbose mode for detailed output\n", BODY_COLOR),
        ("  • Check firewall rules if no ports found\n", BODY_COLOR),
        ("  • Verify target IP accessibility with ping\n", BODY_COLOR),
        ("  • Use smaller port ranges to isolate issues", BODY_COLOR)
    )
    
    console.print(Panel(
        tips_text,
        title=f"[{HEADER_COLOR}]TIPS & BEST PRACTICES[/]",
        border_style=BORDER_COLOR,
        box=ROUNDED
    ))
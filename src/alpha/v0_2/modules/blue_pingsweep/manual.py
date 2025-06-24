from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.box import ROUNDED

console = Console()

def print_help():
    """Exibe a ajuda completa da ferramenta com formatação rica"""
    
    # Define color scheme matching ArpScan manual
    HEADER_COLOR = "bold bright_blue"
    BORDER_COLOR = "bright_white"
    ACCENT_COLOR = "cyan"
    BODY_COLOR = "white"
    
    # Main banner
    console.print(Panel.fit(
        "[bold magenta]PingSweep - Network Host Discovery Tool[/bold magenta]",
        subtitle="[bold yellow]Purple Shiva Tools[/bold yellow]",
        style="magenta",
        box=ROUNDED
    ))
    
    # Interactive Shell Section
    interactive_text = Text.assemble(
        ("Interactive Shell Usage\n\n", HEADER_COLOR),
        ("The PingSweep shell provides an intuitive interface for configuring and "
         "executing network discovery scans:\n\n", BODY_COLOR),
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
        ("  - Automatic report generation in JSON/XML format\n", BODY_COLOR),
        ("  - Multi-threaded scanning for performance\n", BODY_COLOR),
        ("  - CIDR notation and IP range support", BODY_COLOR)
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
    param_table.add_column("Default", style="dim " + BODY_COLOR)
    param_table.add_column("Required", justify="center")
    
    param_table.add_row("0", "IP Range", "Target IPs (CIDR, range, or single IP)", "not set", "[bold red]✓[/bold red]")
    param_table.add_row("1", "Delay", "Time between ping attempts (seconds)", "0.1", "")
    param_table.add_row("2", "Threads", "Maximum number of concurrent threads", "50", "")
    param_table.add_row("3", "Report Format", "Output format (json/xml)", "json", "")
    param_table.add_row("4", "Verbose", "Detailed output mode (true/false)", "false", "")
    
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
    cmd_table.add_row("start", "Execute PingSweep scan", "start")
    cmd_table.add_row("help", "Show command reference", "help")
    cmd_table.add_row("manual", "Display this manual", "manual")
    cmd_table.add_row("clear", "Clear terminal screen", "clear")
    cmd_table.add_row("quit/exit/back", "Return to main menu", "exit")
    
    console.print(cmd_table)
    console.print()
    
    # IP Range Formats Section
    ip_formats_text = Text.assemble(
        ("Supported IP Range Formats\n\n", HEADER_COLOR),
        ("CIDR Notation:\n", ACCENT_COLOR),
        ("  192.168.1.0/24     → Scan entire network (254 hosts)\n", BODY_COLOR),
        ("  10.0.0.0/16        → Scan Class B network (65,534 hosts)\n", BODY_COLOR),
        ("  172.16.0.0/12      → Scan private Class A network\n\n", BODY_COLOR),
        
        ("IP Range with Hyphen:\n", ACCENT_COLOR),
        ("  192.168.1.1-192.168.1.50     → Scan IPs from 1 to 50\n", BODY_COLOR),
        ("  10.0.0.100-10.0.0.200        → Scan IPs from 100 to 200\n\n", BODY_COLOR),
        
        ("Single IP Address:\n", ACCENT_COLOR),
        ("  192.168.1.1        → Test single host\n", BODY_COLOR),
        ("  8.8.8.8            → Test Google DNS server", BODY_COLOR)
    )
    
    console.print(Panel(
        ip_formats_text,
        title=f"[{HEADER_COLOR}]IP RANGE FORMATS[/]",
        border_style=BORDER_COLOR,
        box=ROUNDED
    ))
    
    # Usage Examples
    examples_text = Text.assemble(
        ("Common Usage Examples\n\n", HEADER_COLOR),
        ("Basic Local Network Scan:\n", ACCENT_COLOR),
        ("  $ set 0\n", BODY_COLOR),
        ("  Enter value for IP RANGE: 192.168.1.0/24\n", BODY_COLOR),
        ("  $ start\n\n", BODY_COLOR),
        
        ("Fast Scan with Custom Settings:\n", ACCENT_COLOR),
        ("  $ set ip_range\n", BODY_COLOR),
        ("  Enter value for IP RANGE: 10.0.0.1-10.0.0.100\n", BODY_COLOR),
        ("  $ set delay\n", BODY_COLOR),
        ("  Enter value for DELAY: 0.05\n", BODY_COLOR),
        ("  $ set threads\n", BODY_COLOR),
        ("  Enter value for THREADS: 100\n", BODY_COLOR),
        ("  $ start\n\n", BODY_COLOR),
        
        ("Detailed Scan with XML Report:\n", ACCENT_COLOR),
        ("  $ set 0\n", BODY_COLOR),
        ("  Enter value for IP RANGE: 172.16.32.0/24\n", BODY_COLOR),
        ("  $ set 3\n", BODY_COLOR),
        ("  Enter value for REPORT FORMAT: xml\n", BODY_COLOR),
        ("  $ set verbose\n", BODY_COLOR),
        ("  Enter value for VERBOSE: true\n", BODY_COLOR),
        ("  $ start", BODY_COLOR)
    )
    
    console.print(Panel(
        examples_text,
        title=f"[{HEADER_COLOR}]USAGE EXAMPLES[/]",
        border_style=BORDER_COLOR,
        box=ROUNDED
    ))
    
    # Terminal Mode Section
    terminal_text = Text.assemble(
        ("Command Line Interface\n\n", HEADER_COLOR),
        ("PingSweep also supports direct execution via command line arguments "
         "for automation and scripting:\n\n", BODY_COLOR),
        ("Basic Syntax:\n", ACCENT_COLOR),
        ("  python pingsweep.py -i <ip_range> [options]\n\n", BODY_COLOR),
        ("Required Arguments:\n", ACCENT_COLOR),
        ("  -i/--range        → IP range to scan\n\n", BODY_COLOR),
        ("Optional Arguments:\n", ACCENT_COLOR),
        ("  -d/--delay        → Delay between pings (default: 0.1)\n", BODY_COLOR),
        ("  -t/--threads      → Number of threads (default: 50)\n", BODY_COLOR),
        ("  -f/--format       → Report format (json/xml)\n", BODY_COLOR),
        ("  -v/--verbose      → Enable verbose output\n", BODY_COLOR),
        ("  --version         → Show version information\n\n", BODY_COLOR),
        ("Examples:\n", ACCENT_COLOR),
        ("  python pingsweep.py -i 192.168.1.0/24\n", BODY_COLOR),
        ("  python pingsweep.py -i 10.0.0.1-10.0.0.100 -d 0.2 -t 30 -v\n", BODY_COLOR),
        ("  python pingsweep.py -i 172.16.0.1 --format xml", BODY_COLOR)
    )
    
    console.print(Panel(
        terminal_text,
        title=f"[{HEADER_COLOR}]TERMINAL MODE[/]",
        border_style=BORDER_COLOR,
        box=ROUNDED
    ))
    
    # Performance Guidelines
    performance_text = Text.assemble(
        ("Performance Optimization Guidelines\n\n", HEADER_COLOR),
        ("Thread Configuration:\n", ACCENT_COLOR),
        ("  • Small networks (< 50 hosts):     20-30 threads\n", BODY_COLOR),
        ("  • Medium networks (50-500 hosts):  50-100 threads\n", BODY_COLOR),
        ("  • Large networks (> 500 hosts):    100-200 threads\n\n", BODY_COLOR),
        ("Delay Recommendations:\n", ACCENT_COLOR),
        ("  • Fast local networks:             0.05-0.1 seconds\n", BODY_COLOR),
        ("  • Standard networks:               0.1-0.2 seconds\n", BODY_COLOR),
        ("  • Slow/congested networks:         0.2-0.5 seconds\n", BODY_COLOR),
        ("  • Wi-Fi networks:                  0.2-0.3 seconds\n\n", BODY_COLOR),
        ("General Tips:\n", ACCENT_COLOR),
        ("  • Monitor system resources during large scans\n", BODY_COLOR),
        ("  • Adjust parameters based on network conditions\n", BODY_COLOR),
        ("  • Use verbose mode for troubleshooting", BODY_COLOR)
    )
    
    console.print(Panel(
        performance_text,
        title=f"[{HEADER_COLOR}]⚡ PERFORMANCE OPTIMIZATION[/]",
        border_style=BORDER_COLOR,
        box=ROUNDED
    ))
    
    # Security and Best Practices
    security_text = Text.assemble(
        ("Security and Ethical Guidelines\n\n", HEADER_COLOR),
        ("Legal and Ethical Considerations:\n", ACCENT_COLOR),
        ("  • ALWAYS obtain proper authorization before scanning\n", BODY_COLOR),
        ("  • Only scan networks you own or have explicit permission to test\n", BODY_COLOR),
        ("  • Respect corporate security policies and guidelines\n", BODY_COLOR),
        ("  • Be mindful of network impact during business hours\n\n", BODY_COLOR),
        ("Technical Best Practices:\n", ACCENT_COLOR),
        ("  • Use appropriate delays to avoid network congestion\n", BODY_COLOR),
        ("  • Monitor system resources during execution\n", BODY_COLOR),
        ("  • Keep logs for audit and troubleshooting purposes\n", BODY_COLOR),
        ("  • Test configurations on small ranges first\n", BODY_COLOR),
        ("  • Consider using VPN for remote network testing", BODY_COLOR)
    )
    
    console.print(Panel(
        security_text,
        title=f"[{HEADER_COLOR}]⚠ SECURITY & ETHICS[/]",
        border_style="red",
        box=ROUNDED
    ))
    
    # Troubleshooting Section
    troubleshooting_text = Text.assemble(
        ("Common Issues and Solutions\n\n", HEADER_COLOR),
        ("No Hosts Found:\n", ACCENT_COLOR),
        ("  • Verify you're connected to the correct network\n", BODY_COLOR),
        ("  • Check if the IP range format is correct\n", BODY_COLOR),
        ("  • Ensure target hosts are actually online\n\n", BODY_COLOR),
        ("Frequent Timeouts:\n", ACCENT_COLOR),
        ("  • Increase delay between ping attempts\n", BODY_COLOR),
        ("  • Reduce number of concurrent threads\n", BODY_COLOR),
        ("  • Check network connectivity and stability\n\n", BODY_COLOR),
        ("Permission Errors:\n", ACCENT_COLOR),
        ("  • Run with appropriate privileges (sudo on Linux/Mac)\n", BODY_COLOR),
        ("  • Check firewall settings and exceptions\n", BODY_COLOR),
        ("  • Verify network interface permissions\n\n", BODY_COLOR),
        ("Performance Issues:\n", ACCENT_COLOR),
        ("  • Adjust thread count based on system capabilities\n", BODY_COLOR),
        ("  • Monitor CPU and memory usage during scans\n", BODY_COLOR),
        ("  • Use smaller IP ranges for testing configurations", BODY_COLOR)
    )
    
    console.print(Panel(
        troubleshooting_text,
        title=f"[{HEADER_COLOR}]🔧 TROUBLESHOOTING[/]",
        border_style=BORDER_COLOR,
        box=ROUNDED
    ))
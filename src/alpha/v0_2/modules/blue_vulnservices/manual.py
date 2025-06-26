from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.box import ROUNDED

console = Console()

def print_vulnservices_manual():
    # Define color scheme matching base shell
    HEADER_COLOR = "bold bright_blue"
    BORDER_COLOR = "bright_white"
    ACCENT_COLOR = "cyan"
    BODY_COLOR = "white"
    
    # Main banner
    console.print(Panel.fit(
        "[bold magenta]VulnServices - Vulnerability Scanner Tool[/bold magenta]",
        subtitle="[bold yellow]Purple Shiva Tools[/bold yellow]",
        style="magenta",
        box=ROUNDED
    ))
    
    # Interactive Shell Section
    interactive_text = Text.assemble(
        ("Interactive Shell Usage\n\n", HEADER_COLOR),
        ("The VulnServices shell provides an intuitive interface for configuring and "
         "executing vulnerability scans:\n\n", BODY_COLOR),
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
    
    param_table.add_row("0", "Target IP", "Target IP address or hostname", "[bold red]✓[/bold red]")
    param_table.add_row("1", "Port Range", "Port range (e.g., 1-1000, 80,443)", "[bold red]✓[/bold red]")
    param_table.add_row("2", "Scan Type", "Protocol type (tcp/udp/both)", "")
    param_table.add_row("3", "Timing", "Timing template (0-5)", "")
    param_table.add_row("4", "Report Format", "Output format (json/xml)", "")
    
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
    cmd_table.add_row("start", "Execute vulnerability scan", "start")
    cmd_table.add_row("help", "Show command reference", "help")
    cmd_table.add_row("manual", "Display this manual", "manual")
    cmd_table.add_row("clear", "Clear terminal screen", "clear")
    cmd_table.add_row("quit/exit/back", "Return to main menu", "exit")
    
    console.print(cmd_table)
    console.print()
    
    # Scan Type Details
    scan_types_text = Text.assemble(
        ("Scan Type Configuration\n\n", HEADER_COLOR),
        ("TCP Scan (default):\n", ACCENT_COLOR),
        ("  - Standard TCP connect() scanning\n", BODY_COLOR),
        ("  - Most reliable and widely supported\n", BODY_COLOR),
        ("  - Good for most vulnerability assessments\n\n", BODY_COLOR),
        
        ("UDP Scan:\n", ACCENT_COLOR),
        ("  - UDP port scanning for service discovery\n", BODY_COLOR),
        ("  - Slower but detects UDP-based services\n", BODY_COLOR),
        ("  - Useful for DNS, DHCP, SNMP detection\n\n", BODY_COLOR),
        
        ("Both (TCP + UDP):\n", ACCENT_COLOR),
        ("  - Comprehensive scan of both protocols\n", BODY_COLOR),
        ("  - Maximum coverage but longer execution time\n", BODY_COLOR),
        ("  - Recommended for thorough assessments", BODY_COLOR)
    )
    
    console.print(Panel(
        scan_types_text,
        title=f"[{HEADER_COLOR}]SCAN TYPES[/]",
        border_style=BORDER_COLOR,
        box=ROUNDED
    ))
    
    # Timing Templates
    timing_text = Text.assemble(
        ("Timing Template Reference\n\n", HEADER_COLOR),
        ("T0 (Paranoid):\n", ACCENT_COLOR),
        ("  - Extremely slow and stealthy\n", BODY_COLOR),
        ("  - IDS evasion, serial scanning\n", BODY_COLOR),
        ("  - Use for highly monitored networks\n\n", BODY_COLOR),
        
        ("T1 (Sneaky):\n", ACCENT_COLOR),
        ("  - Slow but less detectable\n", BODY_COLOR),
        ("  - Good balance of stealth and speed\n\n", BODY_COLOR),
        
        ("T2 (Polite):\n", ACCENT_COLOR),
        ("  - Reduces bandwidth usage\n", BODY_COLOR),
        ("  - Slower than normal but respectful\n\n", BODY_COLOR),
        
        ("T3 (Normal - Default):\n", ACCENT_COLOR),
        ("  - Standard scanning speed\n", BODY_COLOR),
        ("  - Balanced performance and accuracy\n\n", BODY_COLOR),
        
        ("T4 (Aggressive):\n", ACCENT_COLOR),
        ("  - Faster scanning with shorter timeouts\n", BODY_COLOR),
        ("  - Good for reliable networks\n\n", BODY_COLOR),
        
        ("T5 (Insane):\n", ACCENT_COLOR),
        ("  - Maximum speed, may miss results\n", BODY_COLOR),
        ("  - Use only on fast, reliable networks", BODY_COLOR)
    )
    
    console.print(Panel(
        timing_text,
        title=f"[{HEADER_COLOR}]TIMING TEMPLATES[/]",
        border_style=BORDER_COLOR,
        box=ROUNDED
    ))
    
    # Usage Examples
    examples_text = Text.assemble(
        ("Common Usage Examples\n\n", HEADER_COLOR),
        ("Basic Web Server Scan:\n", ACCENT_COLOR),
        ("  $ set 0\n", BODY_COLOR),
        ("  Enter value for Target IP: 192.168.1.100\n", BODY_COLOR),
        ("  $ set 1\n", BODY_COLOR),
        ("  Enter value for Port Range: 80,443,8080,8443\n", BODY_COLOR),
        ("  $ start\n\n", BODY_COLOR),
        
        ("Full Port Range Assessment:\n", ACCENT_COLOR),
        ("  $ set target\n", BODY_COLOR),
        ("  Enter value for Target IP: 10.0.0.15\n", BODY_COLOR),
        ("  $ set ports\n", BODY_COLOR),
        ("  Enter value for Port Range: 1-65535\n", BODY_COLOR),
        ("  $ set timing\n", BODY_COLOR),
        ("  Enter value for Timing: 4\n", BODY_COLOR),
        ("  $ start\n\n", BODY_COLOR),
        
        ("Comprehensive UDP + TCP Scan:\n", ACCENT_COLOR),
        ("  $ set 0\n", BODY_COLOR),
        ("  Enter value for Target IP: 172.16.0.1\n", BODY_COLOR),
        ("  $ set 1\n", BODY_COLOR),
        ("  Enter value for Port Range: 1-1000\n", BODY_COLOR),
        ("  $ set scan_type\n", BODY_COLOR),
        ("  Enter value for Scan Type: both\n", BODY_COLOR),
        ("  $ set report_format\n", BODY_COLOR),
        ("  Enter value for Report Format: xml\n", BODY_COLOR),
        ("  $ start\n\n", BODY_COLOR),
        
        ("Stealth Scan for IDS Evasion:\n", ACCENT_COLOR),
        ("  $ set target\n", BODY_COLOR),
        ("  Enter value for Target IP: 203.0.113.50\n", BODY_COLOR),
        ("  $ set ports\n", BODY_COLOR),
        ("  Enter value for Port Range: 21,22,23,25,53,80,110,443\n", BODY_COLOR),
        ("  $ set timing\n", BODY_COLOR),
        ("  Enter value for Timing: 1\n", BODY_COLOR),
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
        ("Command-Line Usage\n\n", HEADER_COLOR),
        ("VulnServices also supports direct command-line execution:\n\n", BODY_COLOR),
        ("Basic Syntax:\n", ACCENT_COLOR),
        ("  vulnservices -t <target> -p <ports> [options]\n\n", BODY_COLOR),
        
        ("Command-Line Examples:\n", ACCENT_COLOR),
        ("  vulnservices -t 192.168.1.100 -p 1-1000\n", BODY_COLOR),
        ("  vulnservices -t 10.0.0.1 -p 80,443,8080 --scan-type both\n", BODY_COLOR),
        ("  vulnservices -t 192.168.1.1 -p 1-65535 --timing 4 --format xml\n", BODY_COLOR),
        ("  vulnservices --help\n\n", BODY_COLOR),
        
        ("Available Options:\n", ACCENT_COLOR),
        ("  -t, --target       Target IP address (required)\n", BODY_COLOR),
        ("  -p, --ports        Port range specification (required)\n", BODY_COLOR),
        ("  -s, --scan-type    Scan type: tcp, udp, both (default: tcp)\n", BODY_COLOR),
        ("  --timing          Timing template 0-5 (default: 3)\n", BODY_COLOR),
        ("  -f, --format      Report format: json, xml (default: json)\n", BODY_COLOR),
        ("  -v, --verbose     Enable verbose output\n", BODY_COLOR),
        ("  --version         Show version information\n", BODY_COLOR),
        ("  --help            Display help message", BODY_COLOR)
    )
    
    console.print(Panel(
        terminal_text,
        title=f"[{HEADER_COLOR}]TERMINAL MODE[/]",
        border_style=BORDER_COLOR,
        box=ROUNDED
    ))
    
    # Port Range Formats
    port_formats_text = Text.assemble(
        ("Port Range Specification Formats\n\n", HEADER_COLOR),
        ("Single Port:\n", ACCENT_COLOR),
        ("  80, 443, 22, 3389\n\n", BODY_COLOR),
        
        ("Multiple Individual Ports:\n", ACCENT_COLOR),
        ("  80,443,8080,8443\n", BODY_COLOR),
        ("  21,22,23,25,53,80,110,143,443,993,995\n\n", BODY_COLOR),
        
        ("Port Ranges:\n", ACCENT_COLOR),
        ("  1-1000        (ports 1 through 1000)\n", BODY_COLOR),
        ("  80-90         (ports 80 through 90)\n", BODY_COLOR),
        ("  1-65535       (all possible ports)\n\n", BODY_COLOR),
        
        ("Mixed Formats:\n", ACCENT_COLOR),
        ("  1-100,443,8000-8080\n", BODY_COLOR),
        ("  80,443,1000-2000,3389,5900-5910\n\n", BODY_COLOR),
        
        ("Common Service Ports:\n", ACCENT_COLOR),
        ("  Web: 80,443,8000,8080,8443\n", BODY_COLOR),
        ("  Mail: 25,110,143,465,587,993,995\n", BODY_COLOR),
        ("  Remote: 22,23,3389,5900-5910\n", BODY_COLOR),
        ("  Database: 1433,1521,3306,5432,27017", BODY_COLOR)
    )
    
    console.print(Panel(
        port_formats_text,
        title=f"[{HEADER_COLOR}]PORT SPECIFICATION[/]",
        border_style=BORDER_COLOR,
        box=ROUNDED
    ))
    
    # Best Practices
    best_practices_text = Text.assemble(
        ("Vulnerability Scanning Best Practices\n\n", HEADER_COLOR),
        ("Pre-Scan Preparation:\n", ACCENT_COLOR),
        ("  • Ensure proper authorization before scanning\n", BODY_COLOR),
        ("  • Verify target scope and boundaries\n", BODY_COLOR),
        ("  • Consider network impact and timing\n", BODY_COLOR),
        ("  • Prepare incident response procedures\n\n", BODY_COLOR),
        
        ("Scan Configuration:\n", ACCENT_COLOR),
        ("  • Start with conservative timing templates\n", BODY_COLOR),
        ("  • Use TCP scans for initial reconnaissance\n", BODY_COLOR),
        ("  • Add UDP scanning for comprehensive coverage\n", BODY_COLOR),
        ("  • Consider stealth options for sensitive environments\n\n", BODY_COLOR),
        
        ("Result Analysis:\n", ACCENT_COLOR),
        ("  • Review both JSON and XML reports\n", BODY_COLOR),
        ("  • Correlate findings with known vulnerabilities\n", BODY_COLOR),
        ("  • Prioritize critical and high-risk findings\n", BODY_COLOR),
        ("  • Document false positives for future reference\n\n", BODY_COLOR),
        
        ("Reporting and Follow-up:\n", ACCENT_COLOR),
        ("  • Generate executive and technical summaries\n", BODY_COLOR),
        ("  • Provide remediation recommendations\n", BODY_COLOR),
        ("  • Schedule regular re-assessment cycles\n", BODY_COLOR),
        ("  • Track remediation progress over time", BODY_COLOR)
    )
    
    console.print(Panel(
        best_practices_text,
        title=f"[{HEADER_COLOR}]BEST PRACTICES[/]",
        border_style=BORDER_COLOR,
        box=ROUNDED
    ))
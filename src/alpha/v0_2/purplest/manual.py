# Enhanced manual.py - Professional Help System
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.box import ROUNDED
from rich.align import Align
from modules import config as conf

# Color scheme constants
HEADER_COLOR = "bold bright_blue"
BORDER_COLOR = "bright_white"
ACCENT_COLOR = "cyan"
BODY_COLOR = "white"
WARNING_COLOR = "bold yellow"
ERROR_COLOR = "bold red"
SUCCESS_COLOR = "bold green"

# Create console with dynamic width handling
try:
    import shutil
    terminal_width = shutil.get_terminal_size().columns
    console = Console(width=terminal_width)
except:
    console = Console()

def print_quick_help():
    """Quick help for shell commands - professional and concise"""
    console.print(f"\n[{HEADER_COLOR}]PurpleShell Commands[/]")
    
    # Create a clean command table
    table = Table(
        show_header=True,
        header_style=HEADER_COLOR,
        border_style=BORDER_COLOR,
        box=ROUNDED,
        padding=(0, 1)
    )
    
    table.add_column("Command", style=ACCENT_COLOR, min_width=12)
    table.add_column("Description", style=BODY_COLOR, min_width=40)
    table.add_column("Example", style="dim " + BODY_COLOR, min_width=20)
    
    # Core commands
    table.add_row("ID", "Select tool by ID number (00-99)", "05")
    table.add_row("start", "Launch selected tool", "start")
    table.add_row("search", "Search tools by name", "search nmap")
    table.add_row("list", "Display tools table", "list")
    table.add_row("info", "Show detailed tool information", "info 05")
    
    # Navigation
    table.add_row("next/prev", "Navigate table pages", "next")
    table.add_row("status", "Show shell status", "status")
    table.add_row("clear", "Clear screen and show table", "clear")
    
    # Meta commands
    table.add_row("help", "Show this help", "help")
    table.add_row("manual", "Show complete manual", "manual")
    table.add_row("quit", "Exit shell", "quit")
    
    console.print(table)
    
    # Professional tips
    console.print(f"\n[{ACCENT_COLOR}]Tips:[/] Use TAB for autocompletion. Type 'manual' for complete documentation.")
    console.print(f"      Use 'help <topic>' for specific help on search, navigation, or tools.\n")

def print_topic_help(topic):
    """Contextual help for specific topics - accurate and professional"""
    topic = topic.lower()
    
    if topic in ["search", "searching"]:
        console.print(f"\n[{HEADER_COLOR}]Search Help[/]")
        console.print(f"[{BODY_COLOR}]Usage: search <tool_name>")
        console.print(f"\n[{ACCENT_COLOR}]Search Functionality:[/]")
        console.print(f"  [{BODY_COLOR}]- Search by exact tool name: search nmap")
        console.print(f"  [{BODY_COLOR}]- Search by partial name: search net")
        console.print(f"  [{BODY_COLOR}]- Case-insensitive matching")
        console.print(f"\n[{WARNING_COLOR}]Note:[/] Current search implementation only matches tool names.")
        console.print(f"      Category and description search are not yet implemented.")
        console.print(f"\n[{ACCENT_COLOR}]Examples:[/]")
        console.print(f"  [{BODY_COLOR}]search nmap           # Find nmap tool")
        console.print(f"  [{BODY_COLOR}]search metasploit     # Find metasploit tools")
        console.print(f"  [{BODY_COLOR}]search wire           # Find wireshark")
        console.print(f"  [{BODY_COLOR}]search scan           # Find tools with 'scan' in name")
        
    elif topic in ["navigation", "nav", "pages"]:
        console.print(f"\n[{HEADER_COLOR}]Navigation Help[/]")
        console.print(f"[{ACCENT_COLOR}]Page Navigation Commands:[/]")
        console.print(f"  [{ACCENT_COLOR}]next[/] (or n)    - Go to next page")
        console.print(f"  [{ACCENT_COLOR}]prev[/] (or p)    - Go to previous page")
        console.print(f"  [{ACCENT_COLOR}]list[/]           - Refresh current page")
        console.print(f"\n[{ACCENT_COLOR}]Tool Selection:[/]")
        console.print(f"  Type tool ID (e.g., 05) to select tool")
        console.print(f"  Type tool name (e.g., nmap) to select tool")
        console.print(f"  Selected tools are highlighted")
        console.print(f"\n[{ACCENT_COLOR}]Examples:[/]")
        console.print(f"  [{BODY_COLOR}]05             # Select tool with ID 05")
        console.print(f"  [{BODY_COLOR}]nmap           # Select nmap tool by name")
        console.print(f"  [{BODY_COLOR}]next           # Go to next page of tools")
        console.print(f"  [{BODY_COLOR}]prev           # Go to previous page")
        
    elif topic in ["tools", "selection"]:
        console.print(f"\n[{HEADER_COLOR}]Tool Management Help[/]")
        console.print(f"[{ACCENT_COLOR}]Tool Selection Methods:[/]")
        console.print(f"  1. Enter tool ID: 05")
        console.print(f"  2. Enter tool name: nmap")
        console.print(f"  3. Use search: search nmap")
        console.print(f"\n[{ACCENT_COLOR}]Tool Information:[/]")
        console.print(f"  info <ID>      - Show detailed tool information")
        console.print(f"  status         - Show currently selected tool")
        console.print(f"  list           - Show all available tools")
        console.print(f"\n[{ACCENT_COLOR}]Tool Execution:[/]")
        console.print(f"  start          - Launch selected tool")
        console.print(f"\n[{ACCENT_COLOR}]Examples:[/]")
        console.print(f"  [{BODY_COLOR}]05             # Select tool ID 05")
        console.print(f"  [{BODY_COLOR}]info 05        # Get information about tool 05")
        console.print(f"  [{BODY_COLOR}]start          # Launch the selected tool")
        console.print(f"  [{BODY_COLOR}]status         # Check what tool is selected")
        
    elif topic in ["startup", "getting-started", "first-time"]:
        console.print(f"\n[{HEADER_COLOR}]Getting Started Guide[/]")
        console.print(f"[{ACCENT_COLOR}]Quick Start Process:[/]")
        console.print(f"  1. Browse tools in the main table")
        console.print(f"  2. Select a tool by typing its ID")
        console.print(f"  3. Launch with 'start' command")
        console.print(f"\n[{ACCENT_COLOR}]Step-by-Step Example:[/]")
        console.print(f"  [{BODY_COLOR}]$ 05           # Select tool with ID 05")
        console.print(f"  [{BODY_COLOR}]$ info 05      # (Optional) Get tool information")
        console.print(f"  [{BODY_COLOR}]$ start        # Launch the selected tool")
        console.print(f"\n[{ACCENT_COLOR}]Alternative Selection Methods:[/]")
        console.print(f"  [{BODY_COLOR}]$ search nmap  # Find nmap tool")
        console.print(f"  [{BODY_COLOR}]$ nmap         # Select nmap directly by name")
        console.print(f"  [{BODY_COLOR}]$ start        # Launch nmap")
        console.print(f"\n[{ACCENT_COLOR}]For More Help:[/]")
        console.print(f"  manual         - Complete documentation")
        console.print(f"  help <topic>   - Specific topic help")
        
    else:
        available_topics = ["search", "navigation", "tools", "startup"]
        console.print(f"\n[{ERROR_COLOR}]Unknown help topic: {topic}[/]")
        console.print(f"[{BODY_COLOR}]Available topics: {', '.join(available_topics)}")
        console.print(f"[{BODY_COLOR}]Usage: help <topic> or just 'help' for command overview")

def print_manual():
    """Complete project manual - professional and accurate"""
    # Main banner - simplified
    banner_content = Text.assemble(
        ("PURPLE SHIVA TOOLS\n", HEADER_COLOR),
        ("Red & Blue Team Cybersecurity project\n", BODY_COLOR),
        (f"Version {conf.VERSION} | {conf.REPO_URL}", "dim " + BODY_COLOR)
    )
    
    console.print(Panel.fit(
        banner_content,
        title=f"[{HEADER_COLOR}]CYBERSECURITY TOOLKIT[/]",
        border_style=BORDER_COLOR
    ))
    
    # project overview - professional tone
    overview = Text.assemble(
        ("License: GPL-3.0\n", ACCENT_COLOR),
        ("Developed by: Purple Shiva Team\n\n", ACCENT_COLOR),
        ("Purple Shiva Tools is an integrated cybersecurity project that combines "
         "offensive security tools and defensive utilities in a unified interactive "
         "shell environment. The project provides a streamlined interface for "
         "penetration testing, security assessment, and network analysis tasks.", BODY_COLOR)
    )
    
    console.print(Panel(
        overview,
        title=f"[{HEADER_COLOR}]project OVERVIEW[/]",
        border_style=BORDER_COLOR
    ))
    
    # Interactive shell section - accurate description
    shell_text = Text.assemble(
        ("Interactive Shell Interface\n\n", HEADER_COLOR),
        ("The project launches PurpleShell, an interactive command environment "
         "that provides the following features:\n\n", BODY_COLOR),
        ("Tool Management:\n", ACCENT_COLOR),
        ("  - Automatic discovery and loading of available tools\n", BODY_COLOR),
        ("  - Categorization of tools by security function\n", BODY_COLOR),
        ("  - Tool indexing with unique ID assignment\n", BODY_COLOR),
        ("  - Simple tool selection by ID or name\n\n", BODY_COLOR),
        ("Search Capabilities:\n", ACCENT_COLOR),
        ("  - Search tools by name (exact and partial matching)\n", BODY_COLOR),
        ("  - Case-insensitive search functionality\n", BODY_COLOR),
        ("  - Real-time result filtering\n\n", BODY_COLOR),
        ("User Interface:\n", ACCENT_COLOR),
        ("  - Paginated tool display (5 tools per page)\n", BODY_COLOR),
        ("  - Clean tabular output format\n", BODY_COLOR),
        ("  - Status indicators for selected tools\n", BODY_COLOR),
        ("  - Command history and tab completion\n", BODY_COLOR),
        ("  - Graceful interrupt handling\n\n", BODY_COLOR),
        ("Navigation:\n", ACCENT_COLOR),
        ("  - Page-based navigation (next/prev commands)\n", BODY_COLOR),
        ("  - Quick tool access by ID or name\n", BODY_COLOR),
        ("  - Context-sensitive help system", BODY_COLOR)
    )
    
    console.print(Panel(
        shell_text,
        title=f"[{HEADER_COLOR}]INTERACTIVE SHELL[/]",
        border_style=BORDER_COLOR
    ))
    
    # Complete command reference - accurate and detailed
    cmd_text = Text.assemble(
        ("Shell Command Reference\n\n", HEADER_COLOR),
        ("Tool Selection and Management:\n", ACCENT_COLOR),
        ("  <ID>          Select tool by ID number (00-99)\n", BODY_COLOR),
        ("                Example: 05\n", BODY_COLOR),
        ("  <name>        Select tool by exact name\n", BODY_COLOR),
        ("                Example: nmap\n", BODY_COLOR),
        ("  start         Launch the currently selected tool\n", BODY_COLOR),
        ("  info <ID>     Show detailed information about a tool\n", BODY_COLOR),
        ("                Example: info 05\n", BODY_COLOR),
        ("  status        Display current selection and project status\n\n", BODY_COLOR),
        
        ("Search and Discovery:\n", ACCENT_COLOR),
        ("  search <term> Search tools by name (partial matching supported)\n", BODY_COLOR),
        ("                Examples:\n", BODY_COLOR),
        ("                  search nmap\n", BODY_COLOR),
        ("                  search net\n", BODY_COLOR),
        ("                  search scan\n", BODY_COLOR),
        ("  list          Refresh and display current tools table\n\n", BODY_COLOR),
        
        ("Navigation and Display:\n", ACCENT_COLOR),
        ("  next          Navigate to next page (alias: n)\n", BODY_COLOR),
        ("  prev          Navigate to previous page (alias: p)\n", BODY_COLOR),
        ("  clear         Clear screen and redisplay tools table\n\n", BODY_COLOR),
        
        ("Help and Information:\n", ACCENT_COLOR),
        ("  help          Show quick command reference\n", BODY_COLOR),
        ("  help <topic>  Get help on specific topics\n", BODY_COLOR),
        ("                Available topics: search, navigation, tools, startup\n", BODY_COLOR),
        ("  manual        Display this complete manual\n\n", BODY_COLOR),
        
        ("Session Control:\n", ACCENT_COLOR),
        ("  quit          Exit the project (alias: exit)\n", BODY_COLOR)
    )
    
    console.print(Panel(
        cmd_text,
        title=f"[{HEADER_COLOR}]COMMAND REFERENCE[/]",
        border_style=BORDER_COLOR
    ))
    
    # Detailed workflow examples
    workflow_text = Text.assemble(
        ("Usage Workflows and Examples\n\n", HEADER_COLOR),
        ("Workflow 1: Quick Tool Launch\n", ACCENT_COLOR),
        ("  Step 1: Browse the tools table when shell starts\n", BODY_COLOR),
        ("  Step 2: Select a tool by typing its ID\n", BODY_COLOR),
        ("          $ 05\n", BODY_COLOR),
        ("  Step 3: Launch the tool\n", BODY_COLOR),
        ("          $ start\n", BODY_COLOR),
        ("  Result: Tool executes in its own interface\n\n", BODY_COLOR),
        
        ("Workflow 2: Search-Based Selection\n", ACCENT_COLOR),
        ("  Step 1: Search for a specific tool\n", BODY_COLOR),
        ("          $ search nmap\n", BODY_COLOR),
        ("  Step 2: Review highlighted search results\n", BODY_COLOR),
        ("  Step 3: Select the desired tool from results\n", BODY_COLOR),
        ("          $ 05\n", BODY_COLOR),
        ("  Step 4: Launch the tool\n", BODY_COLOR),
        ("          $ start\n\n", BODY_COLOR),
        
        ("Workflow 3: Tool Investigation\n", ACCENT_COLOR),
        ("  Step 1: Get detailed information about a tool\n", BODY_COLOR),
        ("          $ info 05\n", BODY_COLOR),
        ("  Step 2: Review tool description and capabilities\n", BODY_COLOR),
        ("  Step 3: Select and launch if appropriate\n", BODY_COLOR),
        ("          $ 05\n", BODY_COLOR),
        ("          $ start\n\n", BODY_COLOR),
        
        ("Workflow 4: Name-Based Selection\n", ACCENT_COLOR),
        ("  Step 1: Select tool directly by name\n", BODY_COLOR),
        ("          $ ping-sweep\n", BODY_COLOR),
        ("  Step 2: Verify selection\n", BODY_COLOR),
        ("          $ status\n", BODY_COLOR),
        ("  Step 3: Launch the tool\n", BODY_COLOR),
        ("          $ start\n\n", BODY_COLOR),
        
        ("Advanced Usage Tips:\n", ACCENT_COLOR),
        ("  - Use TAB completion for commands: sea<TAB> → search\n", BODY_COLOR),
        ("  - Navigate efficiently with next/prev for large tool sets\n", BODY_COLOR),
        ("  - Use search to quickly locate tools by name\n", BODY_COLOR),
        ("  - Check status regularly to verify current selection\n", BODY_COLOR),
        ("  - Access help for specific topics: help search", BODY_COLOR)
    )
    
    console.print(Panel(
        workflow_text,
        title=f"[{HEADER_COLOR}]USAGE WORKFLOWS[/]",
        border_style=BORDER_COLOR
    ))
    
    # Search system - accurate current implementation
    search_text = Text.assemble(
        ("Search System Documentation\n\n", HEADER_COLOR),
        ("Current Search Implementation:\n", ACCENT_COLOR),
        ("The search function currently supports tool name matching only.\n\n", BODY_COLOR),
        ("Supported Search Types:\n", ACCENT_COLOR),
        ("  Name Search:    search nmap\n", BODY_COLOR),
        ("  Partial Match:  search net (matches 'netcat', 'nmap', etc.)\n", BODY_COLOR),
        ("  Case Insensitive: search NMAP (same as 'nmap')\n\n", BODY_COLOR),
        ("Search Examples:\n", ACCENT_COLOR),
        ("  $ search arp           # Find ARP poison tool\n", BODY_COLOR),
        ("  $ search ping          # Find ping sweep tool\n", BODY_COLOR),
        ("  $ search smb           # Find SMB enumeration tool\n", BODY_COLOR),
        ("  $ search enum          # Find tools with 'enum' in name\n", BODY_COLOR),
        ("  $ search poison        # Find ARP poison tool\n", BODY_COLOR),
        ("  $ search sweep         # Find ping sweep tool\n\n", BODY_COLOR),
        ("Search Behavior:\n", ACCENT_COLOR),
        ("  - Results are highlighted in the tools table\n", BODY_COLOR),
        ("  - Pagination is maintained with search results\n", BODY_COLOR),
        ("  - Use next/prev to navigate through search results\n", BODY_COLOR),
        ("  - Use 'list' to return to full tool table\n\n", BODY_COLOR),
        ("Limitations:\n", ACCENT_COLOR),
        ("  - Category-based search not yet implemented\n", BODY_COLOR),
        ("  - Description search not yet implemented\n", BODY_COLOR),
        ("  - Advanced search operators not supported\n\n", BODY_COLOR),
        ("Future Enhancements:\n", ACCENT_COLOR),
        ("  - Category filtering (red team, blue team)\n", BODY_COLOR),
        ("  - Description and keyword search\n", BODY_COLOR),
        ("  - Tag-based search functionality", BODY_COLOR)
    )
    
    console.print(Panel(
        search_text,
        title=f"[{HEADER_COLOR}]SEARCH SYSTEM[/]",
        border_style=BORDER_COLOR
    ))
    
    # Tool categories and capabilities - updated for actual tools
    capabilities = Text.assemble(
        ("project Tool Categories\n\n", HEADER_COLOR),
        ("Red Team Tools (Offensive Security):\n", ACCENT_COLOR),
        ("  - ARP poisoning and man-in-the-middle attacks\n", BODY_COLOR),
        ("  - Network enumeration and host discovery\n", BODY_COLOR),
        ("  - SMB service enumeration and analysis\n", BODY_COLOR),
        ("  - Ping sweeping for network reconnaissance\n", BODY_COLOR),
        ("  - Basic penetration testing utilities\n\n", BODY_COLOR),
        ("Blue Team Tools (Defensive Security):\n", ACCENT_COLOR),
        ("  - Network monitoring and analysis\n", BODY_COLOR),
        ("  - Security assessment and validation\n", BODY_COLOR),
        ("  - Network topology discovery\n", BODY_COLOR),
        ("  - Service enumeration for security auditing\n\n", BODY_COLOR),
        ("project Architecture:\n", ACCENT_COLOR),
        ("  - Modular tool integration system\n", BODY_COLOR),
        ("  - Plugin-based architecture\n", BODY_COLOR),
        ("  - Cross-platform compatibility\n", BODY_COLOR),
        ("  - Session management and logging\n", BODY_COLOR),
        ("  - Automated tool discovery\n", BODY_COLOR),
        ("  - Unified command interface", BODY_COLOR)
    )
    
    console.print(Panel(
        capabilities,
        title=f"[{HEADER_COLOR}]TOOL CATEGORIES[/]",
        border_style=BORDER_COLOR
    ))
    
    # Professional best practices - more concise
    practices_text = Text.assemble(
        ("Security Best Practices and Guidelines\n\n", HEADER_COLOR),
        ("Legal and Ethical Considerations:\n", WARNING_COLOR),
        ("  - Obtain explicit written authorization before testing\n", BODY_COLOR),
        ("  - Define and respect scope boundaries\n", BODY_COLOR),
        ("  - Follow responsible disclosure procedures\n", BODY_COLOR),
        ("  - Maintain detailed documentation of all activities\n", BODY_COLOR),
        ("  - Comply with applicable laws and regulations\n\n", BODY_COLOR),
        ("Operational Security Practices:\n", ACCENT_COLOR),
        ("  - Use isolated testing environments when possible\n", BODY_COLOR),
        ("  - Monitor system resources during operations\n", BODY_COLOR),
        ("  - Implement proper network segmentation\n", BODY_COLOR),
        ("  - Secure all generated reports and evidence\n\n", BODY_COLOR),
        ("Tool Usage Guidelines:\n", ACCENT_COLOR),
        ("  - Begin with passive reconnaissance techniques\n", BODY_COLOR),
        ("  - Validate tool configurations in lab environments\n", BODY_COLOR),
        ("  - Use appropriate timing to avoid service disruption\n", BODY_COLOR),
        ("  - Maintain comprehensive testing logs\n\n", BODY_COLOR),
        ("Results Management:\n", ACCENT_COLOR),
        ("  - Verify and validate all findings\n", BODY_COLOR),
        ("  - Provide clear and actionable remediation guidance\n", BODY_COLOR),
        ("  - Archive results securely with proper retention policies\n", BODY_COLOR),
        ("  - Implement proper access controls for sensitive data", BODY_COLOR)
    )
    
    console.print(Panel(
        practices_text,
        title=f"[{HEADER_COLOR}]SECURITY BEST PRACTICES[/]",
        border_style=BORDER_COLOR
    ))
    
    # Technical requirements - removed unnecessary details
    tech_text = Text.assemble(
        ("project Information\n\n", HEADER_COLOR),
        ("Current Setup:\n", ACCENT_COLOR),
        ("  - Tools are automatically loaded from modules directory\n", BODY_COLOR),
        ("  - Configuration settings stored in modules/config.py\n", BODY_COLOR),
        ("  - Command history maintained in shell session\n\n", BODY_COLOR),
        ("Available Tools:\n", ACCENT_COLOR),
        ("  - ARP Poison: Network man-in-the-middle attacks\n", BODY_COLOR),
        ("  - Ping Sweep: Network host discovery\n", BODY_COLOR),
        ("  - SMB Enumeration: SMB service analysis\n", BODY_COLOR),
        ("  - Additional tools loaded dynamically\n\n", BODY_COLOR),
        ("Tool Categories:\n", ACCENT_COLOR),
        ("  - Red Team: Offensive security tools\n", BODY_COLOR),
        ("  - Blue Team: Defensive security tools\n", BODY_COLOR),
        ("  - Mixed: Tools that serve both purposes", BODY_COLOR)
    )
    
    console.print(Panel(
        tech_text,
        title=f"[{HEADER_COLOR}]TECHNICAL REQUIREMENTS[/]",
        border_style=BORDER_COLOR
    ))
    
    # Troubleshooting section - updated with actual tools
    troubleshooting_text = Text.assemble(
        ("Troubleshooting and Common Issues\n\n", HEADER_COLOR),
        ("Tool Selection Issues:\n", ERROR_COLOR),
        ("  Problem: Tool ID not recognized\n", BODY_COLOR),
        ("  Solution: Use 'list' to see current tool IDs\n", BODY_COLOR),
        ("           Tool IDs may change based on available tools\n\n", BODY_COLOR),
        ("  Problem: Tool name not found\n", BODY_COLOR),
        ("  Solution: Use 'search <partial_name>' to find exact names\n", BODY_COLOR),
        ("           Try: search arp, search ping, search smb\n\n", BODY_COLOR),
        ("Search Problems:\n", WARNING_COLOR),
        ("  Problem: Search returns no results\n", BODY_COLOR),
        ("  Solution: Try partial names:\n", BODY_COLOR),
        ("           - search arp (for ARP poison)\n", BODY_COLOR),
        ("           - search ping (for ping sweep)\n", BODY_COLOR),
        ("           - search enum (for SMB enumeration)\n\n", BODY_COLOR),
        ("  Problem: Expected search features not working\n", BODY_COLOR),
        ("  Solution: Current search only supports name matching\n", BODY_COLOR),
        ("           Category and description search not yet implemented\n\n", BODY_COLOR),
        ("Navigation Issues:\n", ACCENT_COLOR),
        ("  Problem: Cannot navigate to next/previous page\n", BODY_COLOR),
        ("  Solution: Check if additional pages exist with 'status'\n", BODY_COLOR),
        ("           Use 'list' to refresh current page view\n\n", BODY_COLOR),
        ("Tool Execution Problems:\n", ACCENT_COLOR),
        ("  Problem: Tool fails to start\n", BODY_COLOR),
        ("  Solution: Check tool requirements and permissions\n", BODY_COLOR),
        ("           Use 'info <ID>' to review tool prerequisites\n", BODY_COLOR),
        ("           Ensure administrative privileges if required", BODY_COLOR)
    )
    
    console.print(Panel(
        troubleshooting_text,
        title=f"[{HEADER_COLOR}]TROUBLESHOOTING[/]",
        border_style=BORDER_COLOR
    ))
    
    # Contribution and development
    contribute_text = Text.assemble(
        ("Development and Contribution\n\n", HEADER_COLOR),
        (f"Repository: {conf.REPO_URL}\n\n", BODY_COLOR),
        ("Contributing to the Project:\n", ACCENT_COLOR),
        ("  - Report bugs and request features through issue tracking\n", BODY_COLOR),
        ("  - Submit pull requests with new tool integrations\n", BODY_COLOR),
        ("  - Improve documentation and user guides\n", BODY_COLOR),
        ("  - Participate in community discussions\n\n", BODY_COLOR),
        ("Development Guidelines:\n", ACCENT_COLOR),
        ("  - Follow existing code structure and patterns\n", BODY_COLOR),
        ("  - Implement comprehensive error handling\n", BODY_COLOR),
        ("  - Include detailed documentation for new features\n", BODY_COLOR),
        ("  - Test thoroughly across different environments\n", BODY_COLOR),
        ("  - Maintain backward compatibility where possible\n\n", BODY_COLOR),
        ("Code Standards:\n", ACCENT_COLOR),
        ("  - Use Python PEP 8 style guidelines\n", BODY_COLOR),
        ("  - Include docstrings for all functions and classes\n", BODY_COLOR),
        ("  - Implement proper logging and debugging support\n", BODY_COLOR),
        ("  - Handle exceptions gracefully with user feedback", BODY_COLOR)
    )
    
    console.print(Panel(
        contribute_text,
        title=f"[{HEADER_COLOR}]DEVELOPMENT[/]",
        border_style=BORDER_COLOR
    ))
    
    # Legal disclaimer - professional and clear
    console.print(Panel(
        Text.assemble(
            ("LEGAL DISCLAIMER\n\n", HEADER_COLOR),
            ("This cybersecurity project is intended exclusively for authorized "
             "security testing and educational purposes. Users are solely responsible "
             "for ensuring compliance with all applicable laws, regulations, and "
             "organizational policies.\n\n", BODY_COLOR),
            ("Unauthorized access to computer systems, networks, or data is illegal "
             "and may result in criminal prosecution and civil liability. Always "
             "obtain explicit written permission before conducting any security "
             "testing activities.\n\n", ERROR_COLOR),
            ("The developers and contributors of this project assume no "
             "responsibility for misuse or illegal activities conducted with these tools.", BODY_COLOR)
        ),
        title=f"[{HEADER_COLOR}]IMPORTANT LEGAL NOTICE[/]",
        border_style=BORDER_COLOR
    ))

def print_cli_help():
    """Entry point for help system"""
    print_quick_help()

# Export the specific functions that might be called directly
__all__ = ['print_cli_help', 'print_manual', 'print_quick_help', 'print_topic_help']
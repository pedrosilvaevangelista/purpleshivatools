# help.py - Rich-Only Styling Version
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.box import ROUNDED
from modules import config as conf  # Only for version/repo info

# Create console with proper width handling
try:
    import shutil
    terminal_width = shutil.get_terminal_size().columns
    console = Console(width=min(terminal_width, 80))
except:
    console = Console(width=80)

def print_framework_help():
    """Detailed help using only Rich styling"""
    # Main banner
    banner_content = Text.assemble(
        ("PURPLE SHIVA TOOLS\n", "bold magenta"),
        ("Red & Blue Team Framework\n", "bold cyan"),
        (f"Version {conf.VERSION} | {conf.REPO_URL}", "blue")
    )
    
    console.print(Panel.fit(
        banner_content,
        title="[bold] CYBERSECURITY TOOLKIT [/bold]",
        style="bold purple",
        border_style="magenta"
    ))
    
    # Framework overview
    overview = Text.assemble(
        ("License: GPL-3.0\n", "bold yellow"),
        ("Developed by: Purple Shiva Team 🔱\n\n", "bold magenta"),
        ("Purple Shiva Tools is an integrated cybersecurity framework combining "
         "red team offensive capabilities and blue team defensive utilities "
         "in a unified platform. Designed for penetration testers, security "
         "analysts, and network administrators.", "white")
    )
    
    console.print(Panel(
        overview,
        title="[bold]FRAMEWORK OVERVIEW[/bold]",
        border_style="cyan"
    ))
    
    # Capabilities section
    capabilities = Text.assemble(
        ("Key Capabilities:\n\n", "bold underline"),
        ("Red Team Tools:\n", "bold red"),
        ("  • Network reconnaissance and scanning\n"),
        ("  • Vulnerability assessment\n"),
        ("  • Exploitation frameworks\n"),
        ("  • Post-exploitation modules\n\n"),
        ("Blue Team Tools:\n", "bold blue"),
        ("  • Network monitoring\n"),
        ("  • Log analysis\n"),
        ("  • Threat detection\n"),
        ("  • Security hardening\n\n"),
        ("Core Features:\n", "bold magenta"),
        ("  • Unified interface for all tools\n"),
        ("  • Extensible module system\n"),
        ("  • Automated reporting\n"),
        ("  • Customizable workflows")
    )
    
    console.print(Panel(
        capabilities,
        title="[bold]CAPABILITIES[/bold]",
        border_style="purple"
    ))
    
    # Interactive mode section
    interactive_text = Text.assemble(
        ("Interactive Mode Usage\n\n", "bold cyan underline"),
        ("The framework launches in interactive mode by default, providing "
         "a user-friendly interface for tool selection and configuration.\n\n"),
        ("Key Features:\n", "bold"),
        ("  • Dynamic tool loading system\n"),
        ("  • Color-coded parameter tables\n"),
        ("  • Context-sensitive help\n"),
        ("  • Progress visualization\n\n"),
        ("Basic Workflow:\n", "bold"),
        ("  1. Select a tool using the configuration table\n"),
        ("  2. Configure tool parameters as needed\n"),
        ("  3. Launch the tool with ", None),
        ("START", "bold green"),
        (" command\n"),
        ("  4. Review results and generate reports")
    )
    
    console.print(Panel(
        interactive_text,
        title="Interactive Mode",
        border_style="blue"
    ))
    
    # Configuration section
    config_text = Text.assemble(
        ("Configuration Parameters\n\n", "bold cyan underline"),
        ("The framework uses a unified configuration interface:\n\n"),
        ("  • ", None),
        ("SELECTED TOOL", "bold magenta"),
        (": Currently chosen security tool (", None),
        ("REQUIRED", "bold red"),
        (")\n\n"),
        ("To configure:\n"),
        ("  • Type ", None),
        ("0", "bold green"),
        (" to select a tool\n"),
        ("  • Enter the tool name when prompted\n"),
        ("  • Tools are loaded dynamically from the modules directory\n"),
        ("  • Use ", None),
        ("tools print", "bold green"),
        (" to see available options")
    )
    
    console.print(Panel(
        config_text,
        title="Configuration",
        border_style="yellow"
    ))
    
    # Command reference
    cmd_text = Text.assemble(
        ("Interactive Commands\n\n", "bold cyan underline"),
        ("  ", None),
        ("0", "bold green"),
        ("         Configure tool selection\n"),
        ("  ", None),
        ("START", "bold green"),
        ("      Launch selected tool\n"),
        ("  ", None),
        ("HELP", "bold green"),
        ("       Show this help message\n"),
        ("  ", None),
        ("QUIT", "bold green"),
        ("       Exit framework\n"),
        ("  ", None),
        ("EXIT", "bold green"),
        ("       Exit framework\n\n"),
        ("Tool Navigation:\n", "bold"),
        ("  • Each tool has its own interactive interface\n"),
        ("  • Tool-specific help available within each module\n"),
        ("  • Reports are saved in /var/log/purpleshivatools/")
    )
    
    console.print(Panel(
        cmd_text,
        title="Command Reference",
        border_style="green"
    ))
    
    # Examples section
    examples_text = Text.assemble(
        ("Example Workflows\n\n", "bold cyan underline"),
        ("1. ", None),
        ("Launch Ping Sweep tool", "bold"),
        (":\n"),
        ("   • Type ", None),
        ("0", "bold green"),
        (" and press Enter\n"),
        ("   • Enter '", None),
        ("pingsweep", "bold cyan"),
        ("' when prompted\n"),
        ("   • Type ", None),
        ("START", "bold green"),
        (" to execute\n\n"),
        ("2. ", None),
        ("Run Port Scanner", "bold"),
        (":\n"),
        ("   • Type ", None),
        ("0", "bold green"),
        (" and press Enter\n"),
        ("   • Enter '", None),
        ("portscan", "bold cyan"),
        ("' when prompted\n"),
        ("   • Configure scanning parameters\n"),
        ("   • Execute with ", None),
        ("START", "bold green"),
        ("\n\n"),
        ("3. ", None),
        ("Vulnerability Assessment", "bold"),
        (":\n"),
        ("   • Type ", None),
        ("0", "bold green"),
        (" and press Enter\n"),
        ("   • Enter '", None),
        ("vulnscan", "bold cyan"),
        ("' when prompted\n"),
        ("   • Set target and scan profile\n"),
        ("   • Launch assessment")
    )
    
    console.print(Panel(
        examples_text,
        title="Examples",
        border_style="cyan"
    ))
    
    # Best practices
    practices_text = Text.assemble(
        ("Security Best Practices\n\n", "bold cyan underline"),
        ("• ", None),
        ("Legal Compliance", "bold red"),
        (": Always obtain proper authorization\n"),
        ("• ", None),
        ("Resource Management", "bold yellow"),
        (": Monitor system load during scans\n"),
        ("• ", None),
        ("Testing Environment", "bold green"),
        (": Validate tools in lab before production\n"),
        ("• ", None),
        ("Data Handling", "bold blue"),
        (": Secure sensitive reports and findings\n"),
        ("• ", None),
        ("Responsible Disclosure", "bold magenta"),
        (": Follow ethical reporting procedures")
    )
    
    console.print(Panel(
        practices_text,
        title="Security Ethics & Best Practices",
        border_style="red"
    ))
    
    # Contribution section
    contribute_text = Text.assemble(
        ("Contribution Information\n\n", "bold cyan underline"),
        (f"GitHub: {conf.REPO_URL}\n\n"),
        ("We welcome contributions:\n"),
        ("  • Report issues and suggest features\n"),
        ("  • Submit pull requests with new tools\n"),
        ("  • Improve documentation\n"),
        ("  • Share with the security community")
    )
    
    console.print(Panel(
        contribute_text,
        title="Contributions Welcome",
        border_style="magenta"
    ))
    
    # Final note
    console.print(Panel(
        "[bold yellow]Use this framework responsibly and ethically.[/bold yellow]\n"
        "Unauthorized scanning or exploitation is illegal.",
        title="⚠ Legal Disclaimer",
        border_style="red",
        style="bold"
    ))

def print_cli_help():
    """Show framework help"""
    print_framework_help()
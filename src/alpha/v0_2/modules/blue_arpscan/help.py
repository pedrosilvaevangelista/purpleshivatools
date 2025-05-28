from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.box import ROUNDED

console = Console()

def print_help():
    """Exibe a ajuda completa da ferramenta com formatação rica"""
    
    # Banner principal
    console.print(Panel.fit(
        "[bold magenta]ArpScan - Purple Shiva Tools[/bold magenta]",
        subtitle="[bold yellow]Scanner de Rede ARP[/bold yellow]",
        style="magenta",
        box=ROUNDED
    ))
    
    # Seção de Modo Interativo
    console.print(Panel(
        "[bold cyan]MODO INTERATIVO[/bold cyan]\n"
        "Interface amigável para configuração passo a passo\n\n"
        "[bold]Como usar:[/bold]\n"
        "- Digite o número da opção para editar seu valor\n"
        "- Comandos disponíveis: [green]HELP[/green], [yellow]QUIT[/yellow], [cyan]START[/cyan]\n"
        "- Exemplo: digite [green]0[/green] para alterar IP POOL, depois [cyan]START[/cyan] para iniciar",
        title="Interativo",
        border_style="cyan"
    ))
    
    # Tabela de parâmetros
    param_table = Table(title="[bold]Parâmetros Configuráveis[/bold]", box=ROUNDED)
    param_table.add_column("N°", style="cyan", justify="center")
    param_table.add_column("Parâmetro", style="magenta")
    param_table.add_column("Descrição", style="green")
    param_table.add_column("Obrigatório", justify="center")
    
    param_table.add_row("0", "IP POOL", "Range de IPs (ex: 192.168.1.0/24)", "[red]✓[/red]")
    param_table.add_row("1", "DELAY", "Delay entre tentativas (segundos)", "[blue]OPC[/blue]")
    param_table.add_row("2", "TIMEOUT", "Timeout para ping (segundos)", "[blue]OPC[/blue]")
    param_table.add_row("3", "REPORT FORMAT", "Formato do relatório (json/xml)", "[blue]OPC[/blue]")
    param_table.add_row("4", "VERBOSE", "Modo detalhado (true/false)", "[blue]OPC[/blue]")
    
    console.print(param_table)
    
    # Seção de Linha de Comando
    console.print(Panel(
        "[bold cyan]MODO TERMINAL (Linha de Comando)[/bold cyan]\n"
        "Uso direto via argumentos para automação\n\n"
        "[bold]Sintaxe básica:[/bold]\n"
        "  python arpscan.py -r <range> [opções]\n\n"
        "[bold]Argumentos obrigatórios:[/bold]\n"
        "  [red]-r/--range[/red]     → Range de IPs para escanear\n\n"
        "[bold]Opções avançadas:[/bold]\n"
        "  [blue]-d/--delay[/blue]      → Delay entre tentativas (padrão: 0.1s)\n"
        "  [blue]-t/--timeout[/blue]    → Timeout para ping (padrão: 2s)\n"
        "  [blue]--report[/blue]       → Formato do relatório (json/xml)\n"
        "  [blue]-v/--verbose[/blue]    → Modo detalhado",
        title="Terminal",
        border_style="blue"
    ))
    
    # Exemplos de uso
    examples = Text()
    examples.append("Exemplos de uso:\n", style="bold underline yellow")
    examples.append("  Rede CIDR:\n", style="bold")
    examples.append("    python arpscan.py -r 192.168.1.0/24\n\n")
    examples.append("  Range específico:\n", style="bold")
    examples.append("    python arpscan.py -r 10.0.0.1-10.0.0.100 -d 0.5 --report xml\n\n")
    examples.append("  IP único com modo verbose:\n", style="bold")
    examples.append("    python arpscan.py -r 172.16.1.50 -v")
    
    console.print(Panel(
        examples,
        title="[bold]Exemplos Práticos[/bold]",
        border_style="yellow"
    ))
    
    # Formatos suportados
    formats = Text()
    formats.append("Formatos de IP suportados:\n", style="bold underline green")
    formats.append("  • CIDR: 192.168.1.0/24 (rede completa)\n")
    formats.append("  • Range: 192.168.1.1-192.168.1.50\n") 
    formats.append("  • IP único: 192.168.1.100")
    
    console.print(Panel(
        formats,
        title="[bold]Formatos de Entrada[/bold]",
        border_style="green"
    ))
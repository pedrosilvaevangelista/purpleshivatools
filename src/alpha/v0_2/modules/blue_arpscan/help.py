from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.box import ROUNDED

console = Console()

def print_help():
    
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
    
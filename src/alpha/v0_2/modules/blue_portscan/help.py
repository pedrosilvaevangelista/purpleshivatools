# help.py
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
        "[bold magenta]PortScan - Purple Shiva Tools[/bold magenta]",
        subtitle="[bold yellow]Ferramenta De Enumeração de portas[/bold yellow]",
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
        "- Exemplo: digite [green]0[/green] para alterar TARGET IP, depois [cyan]START[/cyan] para iniciar",
        title="Interativo",
        border_style="cyan"
    ))
    
    # Tabela de parâmetros
    param_table = Table(title="[bold]Parâmetros Configuráveis[/bold]", box=ROUNDED)
    param_table.add_column("N°", style="cyan", justify="center")
    param_table.add_column("Parâmetro", style="magenta")
    param_table.add_column("Descrição", style="green")
    param_table.add_column("Obrigatório", justify="center")
    
    param_table.add_row("0", "TARGET IP", "Endereço IP do alvo", "[red]✓[/red]")
    param_table.add_row("1", "PORT RANGE", "Intervalo de portas (ex: 1-1000)", "[red]✓[/red]")
    param_table.add_row("2", "DELAY", "Delay entre tentativas (segundos)", "[blue]OPC[/blue]")
    param_table.add_row("3", "REPORT FORMAT", "Formato do relatório (json/xml)", "[blue]OPC[/blue]")
    param_table.add_row("4", "VERBOSE", "Modo detalhado (true/false)", "[blue]OPC[/blue]")
    
    console.print(param_table)
    
    # Seção de Linha de Comando
    console.print(Panel(
        "[bold cyan]MODO TERMINAL (Linha de Comando)[/bold cyan]\n"
        "Uso direto via argumentos para automação\n\n"
        "[bold]Sintaxe básica:[/bold]\n"
        "  python portscan.py -i <ip> -p <range> [opções]\n\n"
        "[bold]Argumentos obrigatórios:[/bold]\n"
        "  [red]-i/--ip[/red]        → Endereço IP do alvo\n"
        "  [red]-p/--ports[/red]     → Intervalo de portas (ex: 1-1000)\n\n"
        "[bold]Opções avançadas:[/bold]\n"
        "  [blue]-d/--delay[/blue]      → Delay entre tentativas (padrão: 0.1s)\n"
        "  [blue]-r/--report[/blue]     → Formato do relatório (json/xml)\n"
        "  [blue]-v/--verbose[/blue]    → Modo detalhado",
        title="Terminal",
        border_style="blue"
    ))
    
    # Exemplos de uso
    examples = Text()
    examples.append("Exemplos de uso:\n", style="bold underline yellow")
    examples.append("  Teste básico:\n", style="bold")
    examples.append("    python portscan.py -i 192.168.1.100 -p 1-1000\n\n")
    examples.append("  Com opções avançadas:\n", style="bold")
    examples.append("    python portscan.py -i 10.0.0.1 -p 80-443 -d 0.5 -r xml -v\n\n")
    examples.append("  Scan completo:\n", style="bold")
    examples.append("    python portscan.py -i 172.16.0.10 -p 1-65535 -r json")
    
    console.print(Panel(
        examples,
        title="[bold]Exemplos Práticos[/bold]",
        border_style="yellow"
    ))
    
    # Dicas de segurança
    security_tips = Text()
    security_tips.append("Dicas de Segurança e Boas Práticas:\n", style="bold underline red")
    security_tips.append("  • Use delays adequados para evitar sobrecarga\n")
    security_tips.append("  • Sempre obtenha permissão antes de escanear\n")
    security_tips.append("  • Monitore recursos do sistema durante execução\n")
    security_tips.append("  • Nunca use em sistemas de produção sem autorização\n")
    security_tips.append("  • Considere usar VPN quando aplicável")
    
    console.print(Panel(
        security_tips,
        title="[bold]⚠ ATENÇÃO: SEGURANÇA[/bold]",
        border_style="red"
    ))
# help.py
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.box import ROUNDED

console = Console()

def print_help():
    """Exibe a ajuda completa da ferramenta com formatação rica"""
    
    console.print(Panel.fit(
        "[bold magenta]ARP SPOOF - Purple Shiva Tools[/bold magenta]",
        subtitle="[bold yellow]Ferramenta De ARP Spoofing[/bold yellow]",
        style="magenta",
        box=ROUNDED
    ))
    
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
    
    param_table = Table(title="[bold]Parâmetros Configuráveis[/bold]", box=ROUNDED)
    param_table.add_column("N°", style="cyan", justify="center")
    param_table.add_column("Parâmetro", style="magenta")
    param_table.add_column("Descrição", style="green")
    param_table.add_column("Obrigatório", justify="center")
    
    param_table.add_row("0", "TARGET IP", "Endereço IP do alvo", "[red]✓[/red]")
    param_table.add_row("1", "GATEWAY IP", "IP do gateway (auto-detect se vazio)", "[blue]OPC[/blue]")
    param_table.add_row("2", "INTERFACE", "Interface de rede (auto-detect se vazio)", "[blue]OPC[/blue]")
    param_table.add_row("3", "DELAY", "Delay entre pacotes ARP (segundos)", "[blue]OPC[/blue]")
    param_table.add_row("4", "REPORT FORMAT", "Formato do relatório (json/xml)", "[blue]OPC[/blue]")
    
    console.print(param_table)
    
    console.print(Panel(
        "[bold cyan]MODO TERMINAL (Linha de Comando)[/bold cyan]\n"
        "Uso direto via argumentos para automação\n\n"
        "[bold]Sintaxe básica:[/bold]\n"
        "  python arpspoof.py -t <target_ip> [opções]\n\n"
        "[bold]Argumentos obrigatórios:[/bold]\n"
        "  [red]-t/--target[/red]    → Endereço IP do alvo\n\n"
        "[bold]Opções avançadas:[/bold]\n"
        "  [blue]-g/--gateway[/blue]    → IP do gateway (auto-detect se omitido)\n"
        "  [blue]-i/--interface[/blue]  → Interface de rede (auto-detect se omitido)\n"
        "  [blue]-d/--delay[/blue]      → Delay entre pacotes ARP (padrão: 2s)\n"
        "  [blue]-r/--report[/blue]     → Formato do relatório (json/xml)",
        title="Terminal",
        border_style="blue"
    ))
    
    examples = Text()
    examples.append("Exemplos de uso:\n", style="bold underline yellow")
    examples.append("  ARP Spoof básico:\n", style="bold")
    examples.append("    python arpspoof.py -t 192.168.1.100\n\n")
    examples.append("  Com gateway específico:\n", style="bold")
    examples.append("    python arpspoof.py -t 192.168.1.100 -g 192.168.1.1\n\n")
    examples.append("  Completo:\n", style="bold")
    examples.append("    python arpspoof.py -t 192.168.1.100 -g 192.168.1.1 -i eth0 -d 1 -r xml")
    
    console.print(Panel(
        examples,
        title="[bold]Exemplos Práticos[/bold]",
        border_style="yellow"
    ))
    
    security_tips = Text()
    security_tips.append("Dicas de Segurança e Boas Práticas:\n", style="bold underline red")
    security_tips.append("  • Use apenas em redes próprias ou com autorização\n")
    security_tips.append("  • ARP Spoofing pode interromper comunicações\n")
    security_tips.append("  • Sempre pressione Ctrl+C para parar adequadamente\n")
    security_tips.append("  • A ferramenta restaura a tabela ARP ao parar\n")
    security_tips.append("  • Use delays adequados para evitar sobrecarga")
    
    console.print(Panel(
        security_tips,
        title="[bold]⚠ ATENÇÃO: SEGURANÇA[/bold]",
        border_style="red"
    ))
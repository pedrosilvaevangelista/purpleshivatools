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
        "[bold magenta]DHCP STARVATION - Purple Shiva Tools[/bold magenta]",
        subtitle="[bold yellow]Ferramenta de Ataque DHCP Starvation[/bold yellow]",
        style="magenta",
        box=ROUNDED
    ))
    
    console.print(Panel(
        "[bold cyan]MODO INTERATIVO[/bold cyan]\n"
        "Interface amigável para configuração passo a passo\n\n"
        "[bold]Como usar:[/bold]\n"
        "- Digite o número da opção para editar seu valor\n"
        "- Comandos disponíveis: [green]HELP[/green], [yellow]QUIT[/yellow], [cyan]START[/cyan]\n"
        "- Exemplo: digite [green]0[/green] para alterar INTERFACE, depois [cyan]START[/cyan] para iniciar",
        title="Interativo",
        border_style="cyan"
    ))
    
    param_table = Table(title="[bold]Parâmetros Configuráveis[/bold]", box=ROUNDED)
    param_table.add_column("N°", style="cyan", justify="center")
    param_table.add_column("Parâmetro", style="magenta")
    param_table.add_column("Descrição", style="green")
    param_table.add_column("Obrigatório", justify="center")
    
    param_table.add_row("0", "INTERFACE", "Interface de rede (eth0, wlan0)", "[red]✓[/red]")
    param_table.add_row("1", "DELAY", "Delay entre pacotes (segundos)", "[blue]OPC[/blue]")
    param_table.add_row("2", "DURATION", "Duração do ataque (segundos)", "[blue]OPC[/blue]")
    param_table.add_row("3", "VERBOSE", "Modo verboso (true/false)", "[blue]OPC[/blue]")
    param_table.add_row("4", "REPORT FORMAT", "Formato do relatório (json/xml)", "[blue]OPC[/blue]")
    
    console.print(param_table)
    
    console.print(Panel(
        "[bold cyan]MODO TERMINAL (Linha de Comando)[/bold cyan]\n"
        "Uso direto via argumentos para automação\n\n"
        "[bold]Sintaxe básica:[/bold]\n"
        "  python dhcpstarvation.py -i <interface> [opções]\n\n"
        "[bold]Argumentos obrigatórios:[/bold]\n"
        "  [red]-i/--interface[/red] → Interface de rede (ex: eth0, wlan0)\n\n"
        "[bold]Opções avançadas:[/bold]\n"
        "  [blue]-d/--delay[/blue]      → Delay entre pacotes (padrão: 0.1s)\n"
        "  [blue]-t/--duration[/blue]   → Duração do ataque em segundos\n"
        "  [blue]-r/--report[/blue]     → Formato do relatório (json/xml)\n"
        "  [blue]-v/--verbose[/blue]    → Modo verboso",
        title="Terminal",
        border_style="blue"
    ))
    
    examples = Text()
    examples.append("Exemplos de uso:\n", style="bold underline yellow")
    examples.append("  Ataque básico:\n", style="bold")
    examples.append("    python dhcpstarvation.py -i eth0\n\n")
    examples.append("  Com duração limitada:\n", style="bold")
    examples.append("    python dhcpstarvation.py -i wlan0 -t 300 -d 0.05\n\n")
    examples.append("  Modo verboso com relatório:\n", style="bold")
    examples.append("    python dhcpstarvation.py -i eth0 -v -r xml -t 600")
    
    console.print(Panel(
        examples,
        title="[bold]Exemplos Práticos[/bold]",
        border_style="yellow"
    ))
    
    console.print(Panel(
        "[bold red]⚠ AVISO LEGAL ⚠[/bold red]\n\n"
        "Esta ferramenta é destinada EXCLUSIVAMENTE para:\n"
        "• Testes de penetração autorizados\n"
        "• Auditoria de segurança com permissão\n"
        "• Ambiente de laboratório/educacional\n\n"
        "[bold]O uso não autorizado é ILEGAL e pode resultar em:[/bold]\n"
        "• Violação de leis de crimes cibernéticos\n"
        "• Responsabilidade civil e criminal\n"
        "• Interrupção de serviços críticos\n\n"
        "[bold yellow]SEMPRE obtenha autorização antes de usar![/bold yellow]",
        title="[bold]RESPONSABILIDADE LEGAL[/bold]",
        border_style="red"
    ))
    
    security_tips = Text()
    security_tips.append("Como funciona o DHCP Starvation:\n", style="bold underline green")
    security_tips.append("1. Envia múltiplas requisições DHCP DISCOVER\n")
    security_tips.append("2. Cada requisição usa um MAC address único\n")
    security_tips.append("3. Servidor DHCP aloca IPs para cada MAC\n")
    security_tips.append("4. Pool de IPs se esgota rapidamente\n")
    security_tips.append("5. Clientes legítimos não conseguem obter IP\n\n")
    security_tips.append("Defesas recomendadas:\n", style="bold underline blue")
    security_tips.append("• DHCP Snooping em switches\n")
    security_tips.append("• Limitação de taxa de requisições\n")
    security_tips.append("• Monitoramento de MAC addresses\n")
    security_tips.append("• Segmentação de rede")
    
    console.print(Panel(
        security_tips,
        title="[bold]INFORMAÇÕES TÉCNICAS[/bold]",
        border_style="green"
    ))
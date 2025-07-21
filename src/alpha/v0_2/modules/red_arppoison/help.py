# help.py (Corrigido para ARP Poison)
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
        "[bold magenta]ARP POISONER - Purple Shiva Tools[/bold magenta]",
        subtitle="[bold yellow]Ferramenta De ARP Poisoning[/bold yellow]",
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
    
    param_table.add_row("0", "TARGET IP", "Endereço IP da vítima", "[red]✓[/red]")
    param_table.add_row("1", "GATEWAY IP", "IP do gateway (auto-detectar se vazio)", "[blue]OPC[/blue]")
    param_table.add_row("2", "INTERFACE", "Interface de rede (auto-detectar se vazio)", "[blue]OPC[/blue]")
    param_table.add_row("3", "DELAY", "Delay entre pacotes ARP (segundos)", "[blue]OPC[/blue]")
    param_table.add_row("4", "PACKET COUNT", "Número de pacotes (0 = infinito)", "[blue]OPC[/blue]")
    param_table.add_row("5", "REPORT FORMAT", "Formato do relatório (json/xml)", "[blue]OPC[/blue]")
    
    console.print(param_table)
    
    # Seção de Linha de Comando
    console.print(Panel(
        "[bold cyan]MODO TERMINAL (Linha de Comando)[/bold cyan]\n"
        "Uso direto via argumentos para automação\n\n"
        "[bold]Sintaxe básica:[/bold]\n"
        "  sudo python arp_poison.py -t <target_ip> [opções]\n\n"
        "[bold]Argumentos obrigatórios:[/bold]\n"
        "  [red]-t/--target[/red]    → Endereço IP da vítima\n\n"
        "[bold]Opções avançadas:[/bold]\n"
        "  [blue]-g/--gateway[/blue]   → IP do gateway (auto-detect se omitido)\n"
        "  [blue]-i/--interface[/blue] → Interface de rede (auto-detect se omitido)\n"
        "  [blue]-d/--delay[/blue]     → Delay entre pacotes (padrão: 1.0s)\n"
        "  [blue]-c/--count[/blue]     → Número de pacotes (0=infinito)\n"
        "  [blue]-r/--report[/blue]    → Formato do relatório (json/xml)\n"
        "  [blue]-v/--verbose[/blue]   → Modo detalhado",
        title="Terminal",
        border_style="blue"
    ))
    
    # Exemplos de uso
    examples = Text()
    examples.append("Exemplos de uso:\n", style="bold underline yellow")
    examples.append("  Ataque básico:\n", style="bold")
    examples.append("    sudo python arp_poison.py -t 192.168.1.100\n\n")
    examples.append("  Com gateway específico:\n", style="bold")
    examples.append("    sudo python arp_poison.py -t 192.168.1.100 -g 192.168.1.1\n\n")
    examples.append("  Ataque limitado:\n", style="bold")
    examples.append("    sudo python arp_poison.py -t 192.168.1.100 -c 100 -d 0.5\n\n")
    examples.append("  Com interface específica:\n", style="bold")
    examples.append("    sudo python arp_poison.py -t 192.168.1.100 -i eth0 -v")
    
    console.print(Panel(
        examples,
        title="[bold]Exemplos Práticos[/bold]",
        border_style="yellow"
    ))
    
    # Dicas de segurança
    security_tips = Text()
    security_tips.append("Dicas de Segurança e Boas Práticas:\n", style="bold underline red")
    security_tips.append("  • NUNCA use em redes que não são suas\n")
    security_tips.append("  • Sempre obtenha autorização por escrito\n")
    security_tips.append("  • Use apenas para testes éticos e educação\n")
    security_tips.append("  • Monitore o tráfego responsavelmente\n")
    security_tips.append("  • Restaure ARP tables após o teste\n")
    security_tips.append("  • Execute com privilégios de root (sudo)")
    
    console.print(Panel(
        security_tips,
        title="[bold]⚠ ATENÇÃO: SEGURANÇA E ÉTICA[/bold]",
        border_style="red"
    ))
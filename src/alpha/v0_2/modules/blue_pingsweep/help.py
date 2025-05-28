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
        "[bold magenta]█PING SWEEP SCANNER - Purple Shiva Tools[/bold magenta]",
        subtitle="[bold yellow]Ferramenta de Descoberta de Hosts Ativos[/bold yellow]",
        style="magenta",
        box=ROUNDED
    ))
    
    # Seção de Modo Interativo
    console.print(Panel(
        "[bold cyan]MODO INTERATIVO[/bold cyan]\n"
        "Interface amigável para configuração passo a passo\n\n"
        "[bold]Como usar:[/bold]\n"
        "- Digite o número da opção para editar seu valor\n"
        "- Comandos disponíveis: [green]HELP[/green], [yellow]QUIT[/yellow], [cyan]START[/cyan], [blue]QUICK[/blue]\n"
        "- Exemplo: digite [green]0[/green] para alterar IP RANGE, depois [cyan]START[/cyan] para iniciar\n"
        "- Use [blue]QUICK[/blue] para testar os primeiros 10 hosts rapidamente",
        title="Interativo",
        border_style="cyan"
    ))
    
    # Tabela de parâmetros
    param_table = Table(title="[bold]Parâmetros Configuráveis[/bold]", box=ROUNDED)
    param_table.add_column("N°", style="cyan", justify="center")
    param_table.add_column("Parâmetro", style="magenta")
    param_table.add_column("Descrição", style="green")
    param_table.add_column("Exemplos", style="yellow")
    param_table.add_column("Obrigatório", justify="center")
    
    param_table.add_row("0", "IP RANGE", "Range de IPs para escanear", "192.168.1.0/24", "[red]✓[/red]")
    param_table.add_row("1", "DELAY", "Delay entre pings (segundos)", "0.1, 0.5, 1.0", "[blue]OPC[/blue]")
    param_table.add_row("2", "THREADS", "Número máximo de threads", "20, 50, 100", "[blue]OPC[/blue]")
    param_table.add_row("3", "REPORT FORMAT", "Formato do relatório", "json, xml", "[blue]OPC[/blue]")
    param_table.add_row("4", "VERBOSE", "Modo detalhado", "true, false", "[blue]OPC[/blue]")
    
    console.print(param_table)
    
    # Seção de formatos de IP Range
    console.print(Panel(
        "[bold cyan]FORMATOS DE IP RANGE SUPORTADOS[/bold cyan]\n\n"
        "[bold]CIDR Notation:[/bold]\n"
        "  192.168.1.0/24    → Escaneia toda a rede (254 hosts)\n"
        "  10.0.0.0/16       → Escaneia rede classe B (65.534 hosts)\n"
        "  172.16.0.0/12     → Escaneia rede classe A privada\n\n"
        "[bold]Range com hífen:[/bold]\n"
        "  192.168.1.1-192.168.1.50    → Escaneia IPs de 1 a 50\n"
        "  10.0.0.100-10.0.0.200       → Escaneia IPs de 100 a 200\n\n"
        "[bold]IP único:[/bold]\n"
        "  192.168.1.1       → Testa apenas um host específico\n"
        "  8.8.8.8           → Testa DNS público do Google",
        title="Formatos de IP",
        border_style="green"
    ))
    
    # Seção de Linha de Comando
    console.print(Panel(
        "[bold cyan]MODO TERMINAL (Linha de Comando)[/bold cyan]\n"
        "Uso direto via argumentos para automação\n\n"
        "[bold]Sintaxe básica:[/bold]\n"
        "  python pingsweep.py -r <range> [opções]\n\n"
        "[bold]Argumentos obrigatórios:[/bold]\n"
        "  [red]-r/--range[/red]     → Range de IPs (CIDR, range ou IP único)\n\n"
        "[bold]Opções avançadas:[/bold]\n"
        "  [blue]-d/--delay[/blue]      → Delay entre pings (padrão: 0.1s)\n"
        "  [blue]-t/--threads[/blue]    → Número de threads (padrão: 50)\n"
        "  [blue]--report[/blue]       → Formato do relatório (json/xml)\n"
        "  [blue]-v/--verbose[/blue]    → Modo detalhado\n"
        "  [blue]--quick[/blue]        → Scan rápido (primeiros 10 hosts)",
        title="Terminal",
        border_style="blue"
    ))
    
    # Exemplos de uso
    examples = Text()
    examples.append("Exemplos de uso:\n", style="bold underline yellow")
    examples.append("  Scan básico de rede local:\n", style="bold")
    examples.append("    python pingsweep.py -r 192.168.1.0/24\n\n")
    examples.append("  Scan com configurações personalizadas:\n", style="bold")
    examples.append("    python pingsweep.py -r 10.0.0.1-10.0.0.100 -d 0.5 -t 30 -v\n\n")
    examples.append("  Scan rápido para teste:\n", style="bold")
    examples.append("    python pingsweep.py -r 172.16.0.0/24 --quick\n\n")
    examples.append("  Scan completo com relatório XML:\n", style="bold")
    examples.append("    python pingsweep.py -r 192.168.0.0/16 --report xml -v")
    
    console.print(Panel(
        examples,
        title="[bold]Exemplos Práticos[/bold]",
        border_style="yellow"
    ))
    
    # Seção de otimização
    performance_tips = Text()
    performance_tips.append("Dicas de Performance:\n", style="bold underline cyan")
    performance_tips.append("  • Para redes pequenas (< 50 hosts): use 20-30 threads\n")
    performance_tips.append("  • Para redes médias (50-500 hosts): use 50-100 threads\n")
    performance_tips.append("  • Para redes grandes (> 500 hosts): use 100-200 threads\n")
    performance_tips.append("  • Ajuste o delay baseado na latência da rede\n")
    performance_tips.append("  • Use --quick para testes iniciais rápidos\n")
    performance_tips.append("  • Redes Wi-Fi: delay 0.2-0.5s, menos threads\n")
    performance_tips.append("  • Redes cabeadas: delay 0.1s, mais threads")
    
    console.print(Panel(
        performance_tips,
        title="[bold]⚡ OTIMIZAÇÃO DE PERFORMANCE[/bold]",
        border_style="cyan"
    ))
    
    # Dicas de segurança
    security_tips = Text()
    security_tips.append("Dicas de Segurança e Boas Práticas:\n", style="bold underline red")
    security_tips.append("  • SEMPRE obtenha permissão antes de escanear redes\n")
    security_tips.append("  • Use delays adequados para evitar sobrecarga da rede\n")
    security_tips.append("  • Monitore recursos do sistema durante execução\n")
    security_tips.append("  • Evite scans em horários de pico de produção\n")
    security_tips.append("  • Considere usar VPN para testes externos\n")
    security_tips.append("  • Nunca escaneie redes que não são suas\n")
    security_tips.append("  • Respeite políticas de segurança corporativas")
    
    console.print(Panel(
        security_tips,
        title="[bold]⚠ ATENÇÃO: SEGURANÇA E ÉTICA[/bold]",
        border_style="red"
    ))
    
    # Seção de troubleshooting
    troubleshooting = Text()
    troubleshooting.append("Soluções para problemas comuns:\n", style="bold underline magenta")
    troubleshooting.append("  • Nenhum host encontrado: verifique se está na rede correta\n")
    troubleshooting.append("  • Timeouts frequentes: aumente o delay ou reduza threads\n")
    troubleshooting.append("  • Erro de permissão: execute como administrador (Linux/Mac: sudo)\n")
    troubleshooting.append("  • Formato de IP inválido: use CIDR (192.168.1.0/24) ou range\n")
    troubleshooting.append("  • Performance lenta: ajuste threads baseado na sua rede\n")
    troubleshooting.append("  • Firewall bloqueando: configure exceções ou use VPN")
    
    console.print(Panel(
        troubleshooting,
        title="[bold]🔧 TROUBLESHOOTING[/bold]",
        border_style="magenta"
    ))
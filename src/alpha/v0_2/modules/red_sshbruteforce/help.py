from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.box import ROUNDED

console = Console()

#esse código tem a base, porem as informações devem ser validadas antes da primeira versão utilizavel

def print_help():
    """Exibe a ajuda completa da ferramenta com formatação rica"""
    
    # Banner principal
    console.print(Panel.fit(
        "[bold magenta]SSH BruteForce - Purple Shiva Tools[/bold magenta]",
        subtitle="[bold yellow]Ferramenta de teste de força bruta SSH[/bold yellow]",
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
    
    param_table.add_row("0", "TARGET IP", "Endereço IP do servidor SSH", "[red]✓[/red]")
    param_table.add_row("1", "USERNAME", "Nome de usuário para teste", "[red]✓[/red]")
    param_table.add_row("2", "PASSWORD FILE", "Arquivo com lista de senhas", "[red]✓[/red]")
    param_table.add_row("3", "DELAY", "Intervalo entre tentativas (segundos)", "[blue]OPC[/blue]")
    param_table.add_row("4", "REPORT FORMAT", "Formato do relatório (json/xml/pdf)", "[blue]OPC[/blue]")
    
    console.print(param_table)
    
    # Seção de Linha de Comando
    console.print(Panel(
        "[bold cyan]MODO TERMINAL (Linha de Comando)[/bold cyan]\n"
        "Uso direto via argumentos para automação\n\n"
        "[bold]Sintaxe básica:[/bold]\n"
        "  python ssh_bruteforce.py -i <ip> -u <user> -p <senhas> [opções]\n\n"
        "[bold]Argumentos obrigatórios:[/bold]\n"
        "  [red]-i/--ip[/red]        → Endereço IP do alvo\n"
        "  [red]-u/--username[/red]  → Nome de usuário\n"
        "  [red]-p/--passwordFile[/red] → Arquivo com senhas\n\n"
        "[bold]Opções avançadas:[/bold]\n"
        "  [blue]-d/--delay[/blue]      → Delay entre tentativas (padrão: 0.1s)\n"
        "  [blue]-r/--reportFormat[/blue] → Formato do relatório (json/xml/pdf)\n"
        "  [blue]-v/--verbose[/blue]    → Modo detalhado (mostra mais informações)",
        title="Terminal",
        border_style="blue"
    ))
    
    # Exemplos de uso
    examples = Text()
    examples.append("Exemplos de uso:\n", style="bold underline yellow")
    examples.append("  Teste básico:\n", style="bold")
    examples.append("    python ssh_bruteforce.py -i 192.168.1.100 -u admin -p wordlist.txt\n\n")
    examples.append("  Com opções avançadas:\n", style="bold")
    examples.append("    python ssh_bruteforce.py -i 10.0.0.1 -u root -p passwords.txt \\\n")
    examples.append("      -d 0.5 -r xml -v\n\n")
    examples.append("  Modo silencioso (apenas relatório):\n", style="bold")
    examples.append("    python ssh_bruteforce.py -i 172.16.0.10 -u backup -p rockyou.txt > report.log")
    
    console.print(Panel(
        examples,
        title="[bold]Exemplos Práticos[/bold]",
        border_style="yellow"
    ))
    
    # Dicas e recomendações de segurança
    security_tips = Text()
    security_tips.append("Dicas de Segurança e Boas Práticas:\n", style="bold underline red")
    security_tips.append("  • Use delays acima de 0.5s para evitar detecção\n")
    security_tips.append("  • Sempre obtenha permissão por escrito antes de testar\n")
    security_tips.append("  • Monitore recursos do sistema durante execução\n")
    security_tips.append("  • Utilize arquivos de senha específicos para o alvo\n")
    security_tips.append("  • Nunca use em sistemas de produção sem autorização\n")
    security_tips.append("  • Considere usar VPN ou TOR para anonimato quando aplicável")
    
    console.print(Panel(
        security_tips,
        title="[bold]⚠ ATENÇÃO: SEGURANÇA[/bold]",
        border_style="red"
    ))
    
    # Informações adicionais
    console.print(Panel(
        "[bold]Informações Adicionais:[/bold]\n"
        "• Relatórios são salvos no diretório 'logs/'\n"
        "• O arquivo de senhas deve ter uma senha por linha\n"
        "• Pressione Ctrl+C para abortar a qualquer momento\n\n"
        "[bold]Versão:[/bold] 2.1.0\n"
        "[bold]Licença:[/bold] MIT\n"
        "[bold]Repositório:[/bold] github.com/purpleshiva/ssh-bruteforce",
        title="Sobre",
        border_style="green"
    ))

# Exemplo de uso:
if __name__ == "__main__":
    print_help()
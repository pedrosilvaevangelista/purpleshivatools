# recommendations.py
recommendations = [
    {
        "id": 1,
        "title": "Correção Imediata de Vulnerabilidades Críticas",
        "severity": "Crítica",
        "contexto": "CVEs com score CVSS >= 7.0 encontradas pelo Nmap Vulners",
        "description": "Aplicar patches para vulnerabilidades críticas identificadas",
        "specificDetails": {
            "passos_prioritarios": [
                "1. Verificar lista de CVEs no relatório do scan",
                "2. Para cada CVE crítica (CVSS >= 7.0):",
                "   a. Verificar versão do software: 'dpkg -l | grep <software>'",
                "   b. Consultar patches disponíveis no repositório oficial",
                "   c. Aplicar atualizações: 'sudo apt update && sudo apt upgrade <software>'",
                "3. Reiniciar serviços afetados conforme necessário"
            ],
            "exemplos_praticos": {
                "Apache com CVE crítica": [
                    "Verificar versão: 'apache2 -v'",
                    "Atualizar: 'sudo apt upgrade apache2'",
                    "Reiniciar: 'sudo systemctl restart apache2'"
                ],
                "OpenSSH com vulnerabilidades": [
                    "Verificar: 'ssh -V'",
                    "Atualizar: 'sudo apt upgrade openssh-server'",
                    "Testar conectividade após restart"
                ]
            },
            "validacao": [
                "Re-executar scan: 'nmap --script vulners <ip> -p <portas-afetadas>'",
                "Verificar logs de sistema: 'sudo journalctl -xe'"
            ]
        },
        "sources": ["NIST NVD", "CVE Details", "OWASP Top 10"]
    },
    {
        "id": 2,
        "title": "Hardening de Serviços Expostos",
        "severity": "Alta",
        "contexto": "Serviços com versões expostas identificados pelo scan",
        "description": "Configurar segurança adicional em serviços identificados",
        "specificDetails": {
            "passos_prioritarios": [
                "1. Para cada serviço identificado no scan:",
                "   a. Revisar configurações de segurança",
                "   b. Desabilitar banners informativos",
                "   c. Implementar rate limiting",
                "2. Configurar firewall restritivo",
                "3. Implementar monitoramento de logs"
            ],
            "exemplos_praticos": {
                "SSH (porta 22)": [
                    "Desabilitar login root: 'PermitRootLogin no' em /etc/ssh/sshd_config",
                    "Mudar porta padrão: 'Port 2222'",
                    "Configurar fail2ban: 'sudo apt install fail2ban'"
                ],
                "Web servers (80/443)": [
                    "Ocultar versão do servidor",
                    "Configurar headers de segurança",
                    "Implementar WAF se possível"
                ]
            },
            "validacao": [
                "Testar configurações com novo scan",
                "Verificar logs de acesso regularmente"
            ]
        },
        "sources": ["CIS Benchmarks", "SANS Hardening Guides"]
    },
    {
        "id": 3,
        "title": "Implementação de Monitoramento Contínuo",
        "severity": "Média",
        "contexto": "Baseado nos serviços e vulnerabilidades identificadas",
        "description": "Estabelecer monitoramento proativo de segurança",
        "specificDetails": {
            "passos_prioritarios": [
                "1. Configurar alertas para tentativas de exploração",
                "2. Implementar IDS/IPS básico",
                "3. Agendar scans regulares de vulnerabilidade",
                "4. Configurar backup e plano de recuperação"
            ],
            "ferramentas_recomendadas": [
                "OSSEC para HIDS",
                "Fail2ban para proteção de força bruta",
                "Logwatch para análise de logs",
                "Cron jobs para scans automáticos"
            ],
            "validacao": [
                "Testar alertas com ataques simulados",
                "Verificar funcionamento dos backups"
            ]
        },
        "sources": ["NIST Cybersecurity Framework", "ISO 27001"]
    }
]
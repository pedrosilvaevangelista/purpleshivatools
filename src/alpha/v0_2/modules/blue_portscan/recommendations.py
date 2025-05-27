# recommendations.py
recommendations = [
    {
        "id": 1,
        "title": "Bloqueio Imediato de Portas Vulneráveis",
        "severity": "Crítica",
        "contexto": "Baseado nas portas abertas identificadas pelo scan",
        "description": "Fechar portas não essenciais expostas na rede",
        "specificDetails": {
            "passos_prioritarios": [
                "1. Verificar a lista de portas abertas no relatório do scan",
                "2. Para serviços não reconhecidos (status 'Unknown' no scan):",
                "   a. Investigar processo responsável: 'sudo lsof -i :<porta>'",
                "   b. Desativar serviço não autorizado: 'sudo systemctl disable <serviço>'",
                "3. Para serviços necessários, restringir acesso:"
            ],
            "exemplos_praticos": {
                "Caso encontre porta 22 (SSH) aberta publicamente": [
                    "Restringir acesso por IP: 'sudo ufw allow proto tcp from 192.168.1.0/24 to any port 22'",
                    "Ou limitar tentativas: 'sudo apt install fail2ban && sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local'"
                ],
                "Se encontrar portas altas (ex: 5432 PostgreSQL)": [
                    "Adicionar regra emergencial: 'sudo iptables -A INPUT -p tcp --dport 5432 -j DROP && sudo netfilter-persistent save'",
                    "Monitorar tentativas: 'sudo journalctl -f -u postgresql'"
                ]
            },
            "validacao": [
                "Executar novo scan com: 'python3 portscan.py <ip> --range <portas-afetadas>'",
                "Verificar logs: 'sudo tail -f /var/log/ufw.log'"
            ]
        },
        "sources": ["NIST SP 800-115", "OWASP Top 10"]
    },
    {
        "id": 2,
        "title": "🛡️ Hardening de Serviços Identificados",
        "severity": "Alta",
        "contexto": "Baseado nos serviços detectados via banner grabbing",
        "description": "Reforçar segurança de serviços expostos",
        "specificDetails": {
            "passos_prioritarios": [
                "1. Para cada serviço listado como 'open' no relatório:",
                "   a. Atualizar para última versão: 'sudo apt update && sudo apt upgrade <pacote>'",
                "   b. Remover banners informativos (ex: Apache):",
                "      'ServerTokens Prod' no /etc/apache2/conf-enabled/security.conf",
                "2. Autenticação obrigatória para serviços expostos:"
            ],
            "exemplos_praticos": {
                "Se encontrar HTTP/HTTPS (portas 80/443)": [
                    "Configurar WAF: 'sudo apt install modsecurity-crs'",
                    "Forçar HTTPS: 'sudo a2enmod ssl && sudo a2ensite default-ssl'"
                ],
                "Para bancos de dados (ex: MySQL porta 3306)": [
                    "Criar usuário restrito: \"CREATE USER 'appuser'@'localhost' IDENTIFIED BY 'S3nh@F0rt3!';\"",
                    "Revogar privilégios globais: \"REVOKE ALL PRIVILEGES ON *.* FROM 'appuser'@'localhost';\""
                ]
            },
            "validacao": [
                "Testar conexão anônima: 'nc -zv <ip> <porta>'",
                "Verificar banners: 'curl -I http://<ip>:<porta>'"
            ]
        },
        "sources": ["CIS Benchmarks", "PCI DSS 4.0"]
    },
    {
        "id": 3,
        "title": "📈 Monitoramento Ativo de Ameaças",
        "severity": "Média",
        "contexto": "Baseado na frequência de scan detectável",
        "description": "Detectar e alertar sobre atividades suspeitas",
        "specificDetails": {
            "passos_prioritarios": [
                "1. Configurar detecção de port scanning:",
                "   a. Usar padrão de limiar no Fail2Ban:",
                "      '[portscan]' no /etc/fail2ban/jail.local",
                "2. Monitorar conexões incomuns:"
            ],
            "exemplos_praticos": {
                "Alerta para múltiplas conexões TCP": [
                    "Comando: 'sudo tcpdump -nn -c 100 'tcp[tcpflags] == tcp-syn' and dst portrange 1-1000'",
                    "Configurar Zabbix/Prometheus para métricas de rede"
                ],
                "Integração com SIEM": [
                    "Coletar logs do firewall: 'sudo apt install auditd'",
                    "Regra de auditoria: 'sudo auditctl -a exit,always -F arch=b64 -S connect -k network_scan'"
                ]
            },
            "validacao": [
                "Simular scan: 'python3 portscan.py localhost --range 1-100 --threads 50'",
                "Verificar alertas: 'sudo tail -f /var/log/fail2ban.log'"
            ]
        },
        "sources": ["MITRE ATT&CK", "ISO 27001"]
    },
    {
        "id": 4,
        "title": "🔄 Atualização de Serviços Expostos",
        "severity": "Crítica",
        "contexto": "Baseado nas versões detectadas via banner grabbing",
        "description": "Corrigir vulnerabilidades conhecidas",
        "specificDetails": {
            "passos_prioritarios": [
                "1. Para cada serviço no relatório:",
                "   a. Verificar CVE relacionado: 'apt list --upgradable'",
                "   b. Atualizar com patches de segurança:"
            ],
            "exemplos_praticos": {
                "Apache HTTP Server desatualizado": [
                    "Atualizar: 'sudo apt upgrade apache2'",
                    "Verificar assinaturas: 'apache2 -v'"
                ],
                "OpenSSH versão antiga": [
                    "Atualizar: 'sudo apt install openssh-server'",
                    "Reiniciar: 'sudo systemctl restart sshd'"
                ]
            },
            "validacao": [
                "Verificar versão via banner: 'nc -zv <ip> <porta>'",
                "Testar vulnerabilidades: 'nmap --script vuln <ip>'"
            ]
        },
        "sources": ["CVE Database", "SANS Top 20"]
    }
]
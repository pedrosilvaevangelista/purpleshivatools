# recommendations.py
# Recomendações Específicas para Prevenção de Ataques FTP Brute Force

recommendations = [
    {
        "id": 1,
        "titulo": "Limitação de Tentativas de Login",
        "gravidade": "Crítica",
        "descricao": "Impedir ataques automatizados limitando tentativas de autenticação.",
        "detalhes": {
            "passos": [
                "Habilitar bloqueio de IP após número X de tentativas falhas",
                "Configurar tempo de espera progressivo entre tentativas",
                "Integrar com fail2ban ou mecanismo similar"
            ],
            "comandos": [
                "# Exemplo com fail2ban",
                "sudo apt install fail2ban",
                "# Configurar jail local para vsftpd",
                "[vsftpd]",
                "enabled = true",
                "port = ftp",
                "filter = vsftpd",
                "logpath = /var/log/vsftpd.log",
                "maxretry = 3"
            ],
            "ferramentas": ["fail2ban", "CrowdSec"]
        },
        "fontes": ["OWASP Brute Force Mitigation"]
    },
    {
        "id": 2,
        "titulo": "Desabilitar Usuário Anônimo",
        "gravidade": "Alta",
        "descricao": "Reduzir a superfície de ataque restringindo acesso não autenticado.",
        "detalhes": {
            "passos": [
                "Desabilitar login anônimo no servidor FTP",
                "Garantir que todos os usuários tenham credenciais fortes"
            ],
            "comandos": [
                "# Arquivo /etc/vsftpd.conf",
                "anonymous_enable=NO"
            ],
            "ferramentas": ["vsftpd", "ProFTPD"]
        },
        "fontes": ["CIS FTP Benchmarks"]
    },
    {
        "id": 3,
        "titulo": "Auditoria de Acessos e Alertas",
        "gravidade": "Alta",
        "descricao": "Detectar tentativas de força bruta em tempo real.",
        "detalhes": {
            "passos": [
                "Habilitar logs de autenticação detalhados",
                "Criar alertas para múltiplas falhas de login consecutivas",
                "Centralizar logs em SIEM para correlação"
            ],
            "comandos": [
                "# Ativar logs no vsftpd",
                "xferlog_enable=YES",
                "log_ftp_protocol=YES",
                "# Monitorar falhas",
                "grep 'FAIL' /var/log/vsftpd.log"
            ],
            "ferramentas": ["ELK Stack", "Graylog", "Splunk"]
        },
        "fontes": ["NIST SP 800-92"]
    },
    {
        "id": 4,
        "titulo": "Política de Senhas Fortes",
        "gravidade": "Crítica",
        "descricao": "Evitar o uso de senhas previsíveis e fáceis de quebrar.",
        "detalhes": {
            "passos": [
                "Exigir senhas com no mínimo 12 caracteres e 3 tipos de caracteres",
                "Implementar rotação periódica de senhas",
                "Evitar reuso de senhas"
            ],
            "comandos": [
                "# PAM config para senhas fortes",
                "sudo apt install libpam-pwquality",
                "minlen = 12",
                "minclass = 3"
            ],
            "ferramentas": ["pam_pwquality", "LAPS"]
        },
        "fontes": ["NIST SP 800-63B"]
    },
    {
        "id": 5,
        "titulo": "Restringir Acesso por IP",
        "gravidade": "Alta",
        "descricao": "Permitir conexões apenas de redes confiáveis.",
        "detalhes": {
            "passos": [
                "Configurar firewall para aceitar apenas IPs autorizados",
                "Bloquear IPs suspeitos identificados por logs ou inteligência de ameaças"
            ],
            "comandos": [
                "# Exemplo com UFW",
                "ufw allow from 192.168.1.0/24 to any port 21",
                "ufw deny 21"
            ],
            "ferramentas": ["iptables", "CrowdSec", "Fail2Ban"]
        },
        "fontes": ["CIS Controls v8"]
    },
    {
        "id": 6,
        "titulo": "Timeouts e Delays entre Tentativas",
        "gravidade": "Média",
        "descricao": "Tornar ataques automatizados ineficazes ao adicionar atrasos.\n",
        "detalhes": {
            "passos": [
                "Configurar delay incremental após falhas",
                "Utilizar timeouts curtos para sessões inativas"
            ],
            "comandos": [
                "# Exemplo no vsftpd.conf",
                "connect_timeout=10",
                "accept_timeout=30"
            ],
            "ferramentas": ["vsftpd"]
        },
        "fontes": ["OWASP Authentication Cheat Sheet"]
    },
    {
        "id": 7,
        "titulo": "Bloqueio Geográfico e por ASN",
        "gravidade": "Média",
        "descricao": "Reduzir tentativas de força bruta globais usando geofencing.",
        "detalhes": {
            "passos": [
                "Implementar bloqueio por país ou ASN",
                "Bloquear regiões que não deveriam acessar o servidor"
            ],
            "comandos": [
                "# Exemplo com ipset + iptables",
                "ipset create blacklist hash:net",
                "iptables -I INPUT -m set --match-set blacklist src -j DROP"
            ],
            "ferramentas": ["ipset", "GeoIP", "CrowdSec"]
        },
        "fontes": ["CISA Network Defense Guide"]
    }
]

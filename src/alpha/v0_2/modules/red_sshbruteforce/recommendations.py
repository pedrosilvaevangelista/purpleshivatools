#versão em portugues contem erros na hora de exportar acentos

recommendations = [
    {
        "id": 1,
        "titulo": "Use Senhas Fortes e Únicas",
        "gravidade": "Crítica",
        "descricao": "Senhas fracas são a causa #1 de violações SSH. Uma senha forte é sua primeira linha de defesa contra ataques de força bruta.",
        "detalhesEspecificos": {
            "recomendacao": "Crie senhas com pelo menos 12 caracteres combinando maiúsculas, minúsculas, números e símbolos. Nunca reuse senhas entre sistemas.",
            "comoImplementar": [
                "Use um gerenciador de senhas como Bitwarden, 1Password ou KeePass",
                "Gere senhas aleatórias para cada sistema",
                "Defina políticas de expiração de senha (máximo 90-180 dias)",
                "Exija complexidade mínima nas configurações do sistema"
            ],
            "exemplos": {
                "fracas": "senha123, admin, root, 123456",
                "fortes": "Tr0ub4dor&3, MeuC4ch0rr0@casa!, 9#mK2$pL8@vN"
            },
            "comandos": [
                "# Definir complexidade em /etc/pam.d/common-password:",
                "password requisite pam_pwquality.so retry=3 minlen=12 difok=3"
            ]
        },
        "fontes": [
            "Diretrizes de Identidade Digital NIST SP 800-63B",
            "OWASP Guia de Autenticação",
            "Guia de Políticas de Senha SANS"
        ]
    },
    {
        "id": 2,
        "titulo": "Ative Autenticação em Dois Fatores (2FA)",
        "gravidade": "Crítica",
        "descricao": "2FA torna sua conta 99.9% mais segura ao exigir um segundo passo de verificação, mesmo que sua senha seja comprometida.",
        "detalhesEspecificos": {
            "recomendacao": "Ative 2FA usando aplicativos autenticadores ou tokens físicos. SMS é melhor que nada mas menos seguro que métodos baseados em app.",
            "comoImplementar": [
                "Instale o módulo PAM do Google Authenticator",
                "Configure SSH para exigir senha e token",
                "Distribua QR codes para configuração móvel",
                "Mantenha códigos de backup em local seguro"
            ],
            "comandos": [
                "# Instalar Google Authenticator PAM",
                "sudo apt-get install libpam-google-authenticator",
                "# Configurar usuário",
                "google-authenticator",
                "# Editar /etc/pam.d/sshd, adicione:",
                "auth required pam_google_authenticator.so",
                "# Editar /etc/ssh/sshd_config:",
                "ChallengeResponseAuthentication yes",
                "AuthenticationMethods publickey,keyboard-interactive"
            ],
            "ferramentas": ["Google Authenticator", "Authy", "Microsoft Authenticator", "YubiKey", "RSA SecurID"]
        },
        "fontes": [
            "NIST 800-63B Autenticação Multifator",
            "Documentação do Google Authenticator PAM",
            "OWASP Guia de Autenticação em Dois Fatores"
        ]
    },
    {
        "id": 3,
        "titulo": "Use Autenticação por Chave SSH em vez de Senhas",
        "gravidade": "Alta",
        "descricao": "Chaves SSH são exponencialmente mais seguras que senhas e eliminam completamente o risco de ataques de força bruta.",
        "detalhesEspecificos": {
            "recomendacao": "Gere pares de chaves SSH fortes (RSA 4096-bit ou Ed25519) e desative completamente a autenticação por senha.",
            "comoImplementar": [
                "Gere par de chaves SSH na máquina cliente",
                "Copie a chave pública para authorized_keys no servidor",
                "Teste login por chave antes de desativar senhas",
                "Defina permissões adequadas nos arquivos de chave",
                "Use ssh-agent para gerenciamento de chaves"
            ],
            "comandos": [
                "# Gerar chave Ed25519 (recomendado)",
                "ssh-keygen -t ed25519 -C 'usuario@empresa.com'",
                "# Ou chave RSA 4096-bit",
                "ssh-keygen -t rsa -b 4096 -C 'usuario@empresa.com'",
                "# Copiar para servidor",
                "ssh-copy-id usuario@servidor",
                "# Definir permissões",
                "chmod 700 ~/.ssh",
                "chmod 600 ~/.ssh/authorized_keys",
                "# Desativar autenticação por senha em /etc/ssh/sshd_config:",
                "PasswordAuthentication no",
                "PubkeyAuthentication yes"
            ]
        },
        "fontes": [
            "OpenSSH Guia de Gerenciamento de Chaves",
            "NIST SP 800-57 Gerenciamento de Chaves",
            "RFC 4716 Formato de Arquivo de Chave Pública SSH"
        ]
    },
    {
        "id": 4,
        "titulo": "Altere a Porta Padrão do SSH",
        "gravidade": "Média",
        "descricao": "Mudar o SSH da porta 22 reduz ataques automatizados em 90%+ pois a maioria dos bots varre portas comuns.",
        "detalhesEspecificos": {
            "recomendacao": "Mude a porta SSH para uma não padrão entre 1024-65535, evitando portas de serviços conhecidos.",
            "comoImplementar": [
                "Escolha uma porta aleatória não usada por outros serviços",
                "Atualize configuração do SSH",
                "Atualize regras de firewall",
                "Informe usuários sobre a nova porta",
                "Teste conectividade antes de finalizar"
            ],
            "comandos": [
                "# Editar /etc/ssh/sshd_config:",
                "Port 2849  # Exemplo de porta não padrão",
                "# Atualizar firewall (exemplo UFW):",
                "sudo ufw allow 2849/tcp",
                "sudo ufw delete allow 22/tcp",
                "# Reiniciar serviço SSH:",
                "sudo systemctl restart sshd",
                "# Conectar usando nova porta:",
                "ssh -p 2849 usuario@servidor"
            ],
            "portasRecomendadas": ["2849", "3847", "4923", "7823", "9284"],
            "portasEvitar": ["80", "443", "25", "53", "110", "993", "995"]
        },
        "fontes": [
            "SANS Guia de Hardening SSH",
            "Controles CIS de Implementação",
            "Boas Práticas de Segurança Linux"
        ]
    },
    {
        "id": 5,
        "titulo": "Desative Login Root via SSH",
        "gravidade": "Crítica",
        "descricao": "A conta root é a mais visada por atacantes. Desativar acesso root via SSH força atacantes a comprometer um usuário comum primeiro.",
        "detalhesEspecificos": {
            "recomendacao": "Desative completamente login root via SSH e use sudo para tarefas administrativas. Crie usuários administrativos dedicados.",
            "comoImplementar": [
                "Crie contas de usuário administrativas",
                "Conceda privilégios sudo a usuários admin",
                "Desative login root via SSH",
                "Teste acesso admin antes de desconectar",
                "Monitore uso de sudo com logging"
            ],
            "comandos": [
                "# Criar usuário admin:",
                "sudo adduser adminuser",
                "# Adicionar ao grupo sudo:",
                "sudo usermod -aG sudo adminuser",
                "# Editar /etc/ssh/sshd_config:",
                "PermitRootLogin no",
                "# Reiniciar SSH:",
                "sudo systemctl restart sshd",
                "# Ativar log sudo em /etc/rsyslog.conf:",
                "auth,authpriv.*                 /var/log/auth.log"
            ]
        },
        "fontes": [
            "Manual de Configuração do OpenSSH Server",
            "Benchmarks CIS para Hardening SSH",
            "NIST Cybersecurity Framework"
        ]
    },
    {
        "id": 6,
        "titulo": "Implemente Fail2Ban para Prevenção de Intrusão",
        "gravidade": "Alta",
        "descricao": "Fail2Ban bloqueia automaticamente IPs após tentativas de login falhas, parando ataques de força bruta em tempo real.",
        "detalhesEspecificos": {
            "recomendacao": "Instale e configure Fail2Ban para monitorar logs SSH e banir automaticamente IPs atacantes por períodos crescentes.",
            "comoImplementar": [
                "Instale pacote Fail2Ban",
                "Configure settings de jail para SSH",
                "Defina tempos de ban progressivos",
                "Monitore logs de ban regularmente",
                "Whitelist faixas de IP confiáveis"
            ],
            "comandos": [
                "# Instalar Fail2Ban:",
                "sudo apt-get install fail2ban",
                "# Criar config local /etc/fail2ban/jail.local:",
                "[sshd]",
                "enabled = true",
                "port = ssh",
                "filter = sshd",
                "logpath = /var/log/auth.log",
                "maxretry = 3",
                "bantime = 3600",
                "findtime = 600",
                "# Iniciar serviço:",
                "sudo systemctl enable fail2ban",
                "sudo systemctl start fail2ban",
                "# Verificar status:",
                "sudo fail2ban-client status sshd"
            ],
            "configsRecomendadas": {
                "maxretry": "3-5 tentativas",
                "bantime": "1 hora inicialmente, aumentando para reincidentes",
                "findtime": "Janela de 10 minutos"
            }
        },
        "fontes": [
            "Documentação Oficial do Fail2Ban",
            "Guia de Detecção de Intrusão Linux",
            "OWASP Prevenção de Ameaças Automatizadas"
        ]
    },
    {
        "id": 7,
        "titulo": "Restrinja Acesso SSH por Endereço IP",
        "gravidade": "Alta",
        "descricao": "Limitar acesso SSH a faixas IP específicas reduz sua superfície de ataque em 95% pois atacantes de redes não autorizadas não podem se conectar.",
        "detalhesEspecificos": {
            "recomendacao": "Use regras de firewall e configuração SSH para permitir conexões apenas de redes confiáveis como escritório ou VPN.",
            "comoImplementar": [
                "Identifique faixas IP confiáveis (escritório, VPN, casa)",
                "Configure regras de firewall",
                "Use diretivas AllowUsers ou AllowGroups do SSH",
                "Teste acesso de locais permitidos",
                "Documente mudanças de IP para a equipe"
            ],
            "comandos": [
                "# Exemplos UFW firewall:",
                "sudo ufw allow from 203.0.113.0/24 to any port 22",
                "sudo ufw allow from 198.51.100.50 to any port 22",
                "# Config SSH em /etc/ssh/sshd_config:",
                "AllowUsers user1@203.0.113.* user2@198.51.100.50",
                "# Ou por grupo:",
                "AllowGroups sshusers",
                "# Negar todos outros:",
                "DenyUsers *",
                "# Reiniciar SSH:",
                "sudo systemctl restart sshd"
            ],
            "exemplos": {
                "escritorio": "203.0.113.0/24 (rede do escritório)",
                "vpn": "10.8.0.0/24 (clientes VPN)",
                "casa": "198.51.100.50/32 (IP específico de casa)"
            }
        },
        "fontes": [
            "Guia de Configuração de Firewall Linux",
            "Documentação de Controle de Acesso OpenSSH",
            "Boas Práticas de Segurança de Rede"
        ]
    },
    {
        "id": 8,
        "titulo": "Ative Logging e Monitoramento SSH",
        "gravidade": "Média",
        "descricao": "Logs adequados ajudam a detectar ataques cedo e fornecem evidências forenses. Muitas violações passam meses sem detecção sem monitoramento adequado.",
        "detalhesEspecificos": {
            "recomendacao": "Configure logs SSH detalhados, centralize logs e configure alertas para atividades suspeitas como múltiplos logins falhos.",
            "comoImplementar": [
                "Ative logging verboso do SSH",
                "Configure rotação de logs",
                "Configure ferramentas de monitoramento",
                "Crie alertas para logins falhos",
                "Procedimentos regulares de revisão de logs"
            ],
            "comandos": [
                "# Ativar logging verboso em /etc/ssh/sshd_config:",
                "LogLevel VERBOSE",
                "SyslogFacility AUTH",
                "# Configurar rsyslog para SSH em /etc/rsyslog.conf:",
                "auth,authpriv.*                 /var/log/auth.log",
                "# Configurar rotação em /etc/logrotate.d/rsyslog:",
                "/var/log/auth.log {",
                "    weekly",
                "    rotate 52",
                "    compress",
                "    delaycompress",
                "}",
                "# Monitorar logins falhos:",
                "grep 'Failed password' /var/log/auth.log | tail -20"
            ],
            "ferramentasMonitoramento": ["ELK Stack", "Splunk", "Graylog", "LogWatch", "OSSEC"],
            "eventosChave": [
                "Tentativas de login falhas",
                "Logins bem-sucedidos de novos IPs",
                "Múltiplas sessões concorrentes",
                "Tentativas de login fora do horário comercial"
            ]
        },
        "fontes": [
            "Guia de System Logging Linux",
            "Diretrizes de Gerenciamento de Logs NIST",
            "Manual de Análise de Logs SANS"
        ]
    },
    {
        "id": 9,
        "titulo": "Defina Timeout de Sessão e Limites de Conexão",
        "gravidade": "Média",
        "descricao": "Sessões ociosas e conexões ilimitadas fornecem mais oportunidades para atacantes. Limites adequados reduzem tempo de exposição e consumo de recursos.",
        "detalhesEspecificos": {
            "recomendacao": "Configure logout automático para sessões ociosas e limite conexões concorrentes por usuário para prevenir ataques de exaustão de recursos.",
            "comoImplementar": [
                "Defina intervalos client alive",
                "Configure máximo de sessões por usuário",
                "Defina tempos limite de login",
                "Implemente throttling de conexão",
                "Monitore sessões ativas regularmente"
            ],
            "comandos": [
                "# Configurar em /etc/ssh/sshd_config:",
                "ClientAliveInterval 300    # 5 minutos",
                "ClientAliveCountMax 2      # 2 heartbeats perdidos = desconectar",
                "LoginGraceTime 60          # 1 minuto para completar login",
                "MaxSessions 2              # Máximo 2 sessões por usuário",
                "MaxStartups 10:30:60       # Throttling de conexão",
                "# Definir timeout de shell em /etc/profile:",
                "export TMOUT=1800          # Timeout de shell de 30 minutos",
                "# Monitorar sessões ativas:",
                "who",
                "w",
                "last"
            ],
            "timeoutsRecomendados": {
                "ClientAliveInterval": "300 segundos (5 minutos)",
                "Shell timeout": "1800 segundos (30 minutos)",
                "LoginGraceTime": "60 segundos"
            }
        },
        "fontes": [
            "Boas Práticas de Configuração SSH",
            "Guia de Hardening de Segurança Linux",
            "Guia do Administrador de Sistemas"
        ]
    },
    {
        "id": 10,
        "titulo": "Use Banners SSH e Avisos Legais",
        "gravidade": "Baixa",
        "descricao": "Banners legais estabelecem políticas de uso autorizado e podem dissuadir atacantes casuais enquanto fornecem proteção legal.",
        "detalhesEspecificos": {
            "recomendacao": "Exiba mensagens claras sobre uso autorizado apenas, monitoramento e consequências legais para acesso não autorizado.",
            "comoImplementar": [
                "Crie arquivo de banner com aviso legal",
                "Configure SSH para exibir banner",
                "Inclua notificação de monitoramento",
                "Revise com equipe jurídica",
                "Atualize regularmente conforme necessário"
            ],
            "comandos": [
                "# Criar arquivo /etc/ssh/banner.txt:",
                "echo 'AVISO: Acesso Autorizado Apenas' > /etc/ssh/banner.txt",
                "echo 'Este sistema é monitorado.' >> /etc/ssh/banner.txt",
                "echo 'Acesso não autorizado é proibido.' >> /etc/ssh/banner.txt",
                "# Configurar em /etc/ssh/sshd_config:",
                "Banner /etc/ssh/banner.txt",
                "# Reiniciar SSH:",
                "sudo systemctl restart sshd"
            ],
            "exemploBanner": """
╔══════════════════════════════════════════════════════════════════╗
║                          AVISO                                   ║
║                                                                  ║
║  Este sistema é para usuários autorizados apenas. Toda atividade ║
║  é monitorada e registrada. Acesso não autorizado é estritamente ║
║  proibido e será processado na máxima extensão da lei.           ║
║                                                                  ║
║  Ao continuar, você reconhece que tem acesso autorizado          ║
║  a este sistema.                                                 ║
╚══════════════════════════════════════════════════════════════════╝
            """
        },
        "fontes": [
            "Diretrizes Legais para Banners de Sistema",
            "Lei de Fraude e Abuso Computacional",
            "Modelos de Política de Segurança Corporativa"
        ]
    },
    {
        "id": 11,
        "titulo": "Implemente Rate Limiting e Throttling de Conexão",
        "gravidade": "Média",
        "descricao": "Rate limiting previne tentativas rápidas de conexão que caracterizam ataques de força bruta, tornando ataques automatizados significativamente mais lentos.",
        "detalhesEspecificos": {
            "recomendacao": "Configure SSH e firewall para limitar tentativas de conexão por minuto do mesmo endereço IP.",
            "comoImplementar": [
                "Configure parâmetro MaxStartups do SSH",
                "Use iptables para rate limiting",
                "Configure técnicas tarpit para atacantes persistentes",
                "Monitore padrões de tentativas de conexão",
                "Ajuste limites baseado em uso legítimo"
            ],
            "comandos": [
                "# Throttling SSH em /etc/ssh/sshd_config:",
                "MaxStartups 10:30:100     # Começa a descartar em 10, recusa em 100",
                "# Rate limiting iptables:",
                "iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set",
                "iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP",
                "# Rate limiting UFW:",
                "ufw limit ssh",
                "# Monitorar tentativas:",
                "netstat -tn | grep :22 | wc -l"
            ],
            "limitesRecomendados": {
                "conexoesPorMinuto": "3-5 tentativas",
                "maxConexoesConcorrentes": "10-20 por IP",
                "periodoCortesia": "60-300 segundos"
            }
        },
        "fontes": [
            "Documentação iptables",
            "Guia de Hardening SSH",
            "Boas Práticas de Proteção DDoS"
        ]
    },
    {
        "id": 12,
        "titulo": "Atualizações de Segurança Regulares e Gerenciamento de Patches",
        "gravidade": "Crítica",
        "descricao": "Software SSH desatualizado contém vulnerabilidades conhecidas que atacantes exploram ativamente. Atualizações regulares são essenciais para segurança.",
        "detalhesEspecificos": {
            "recomendacao": "Estabeleça procedimentos automatizados de atualização para SSH e componentes relacionados, com teste em ambientes não produtivos primeiro.",
            "comoImplementar": [
                "Ative atualizações de segurança automáticas",
                "Assine alertas de segurança",
                "Teste atualizações em ambiente staging",
                "Agende janelas de manutenção regulares",
                "Mantenha inventário de versões SSH"
            ],
            "comandos": [
                "# Verificar versão atual:",
                "ssh -V",
                "sshd -V",
                "# Atualizar SSH (Ubuntu/Debian):",
                "sudo apt update && sudo apt upgrade openssh-server",
                "# Atualizar SSH (CentOS/RHEL):",
                "sudo yum update openssh-server",
                "# Ativar atualizações automáticas (Ubuntu):",
                "sudo apt install unattended-upgrades",
                "sudo dpkg-reconfigure -plow unattended-upgrades",
                "# Verificar atualizações disponíveis:",
                "apt list --upgradable | grep ssh"
            ],
            "cronogramaAtualizacao": {
                "atualizacoesSeguranca": "Dentro de 24-48 horas após lançamento",
                "atualizacoesRegulares": "Janelas mensais de manutenção",
                "patchesEmergenciais": "Imediatamente para vulnerabilidades críticas"
            }
        },
        "fontes": [
            "Alertas de Segurança OpenSSH",
            "Banco de Dados CVE",
            "NIST National Vulnerability Database"
        ]
    },
    {
        "id": 13,
        "titulo": "Use Configurações de Hardening e Segurança SSH",
        "gravidade": "Alta",
        "descricao": "Configurações padrão do SSH priorizam compatibilidade sobre segurança. Hardening elimina protocolos e cifras fracas.",
        "detalhesEspecificos": {
            "recomendacao": "Desative protocolos fracos, use cifras fortes e configure parâmetros SSH seguros de acordo com padrões atuais.",
            "comoImplementar": [
                "Desative versão 1 do protocolo SSH",
                "Use algoritmos de criptografia fortes",
                "Desative métodos fracos de autenticação",
                "Configure métodos seguros de troca de chaves",
                "Auditorias regulares de configuração"
            ],
            "comandos": [
                "# Configuração segura em /etc/ssh/sshd_config:",
                "Protocol 2",
                "PermitEmptyPasswords no",
                "X11Forwarding no",
                "AllowAgentForwarding no",
                "AllowTcpForwarding no",
                "PermitUserEnvironment no",
                "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com",
                "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com",
                "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512",
                "# Testar configuração:",
                "sudo sshd -t",
                "# Aplicar mudanças:",
                "sudo systemctl restart sshd"
            ],
            "recursosSeguranca": [
                "Apenas cifras fortes",
                "Algoritmos MAC seguros",
                "Métodos modernos de troca de chaves",
                "Recursos desnecessários desativados",
                "Apenas versão 2 do protocolo"
            ]
        },
        "fontes": [
            "Diretrizes de Segurança SSH Mozilla",
            "Benchmarks CIS para SSH",
            "Padrões Criptográficos NIST"
        ]
    },
    {
        "id": 14,
        "titulo": "Implemente Autoridade Certificadora (CA) SSH",
        "gravidade": "Média",
        "descricao": "SSH CA fornece gerenciamento centralizado de chaves, rotação automática e controle de acesso refinado para ambientes grandes.",
        "detalhesEspecificos": {
            "recomendacao": "Para organizações com múltiplos servidores, implemente SSH CA para gerenciamento escalável de chaves e controles de segurança avançados.",
            "comoImplementar": [
                "Configure Autoridade Certificadora SSH",
                "Gere chave de assinatura CA",
                "Configure servidores para confiar na CA",
                "Emita certificados de usuário",
                "Implemente gerenciamento de ciclo de vida"
            ],
            "comandos": [
                "# Gerar chave CA:",
                "ssh-keygen -t rsa -b 4096 -f ssh_ca",
                "# Assinar certificado de usuário:",
                "ssh-keygen -s ssh_ca -I usuario1 -n usuario1 -V +1w ~/.ssh/id_rsa.pub",
                "# Configurar servidor para confiar em CA em /etc/ssh/sshd_config:",
                "TrustedUserCAKeys /etc/ssh/ssh_ca.pub",
                "# Usuário conecta com certificado:",
                "ssh -o CertificateFile=~/.ssh/id_rsa-cert.pub usuario@servidor"
            ],
            "beneficios": [
                "Controle de acesso centralizado",
                "Rotação automática de chaves",
                "Permissões refinadas",
                "Rastreamento de auditoria",
                "Gerenciamento simplificado"
            ]
        },
        "fontes": [
            "OpenSSH Autenticação por Certificado",
            "Gerenciamento de Chaves SSH Empresarial",
            "Guia de Boas Práticas PKI"
        ]
    },
    {
        "id": 15,
        "titulo": "Segmentação de Rede e Acesso VPN",
        "gravidade": "Alta",
        "descricao": "Isolar servidores SSH em segmentos protegidos e exigir VPN adiciona múltiplas camadas de segurança.",
        "detalhesEspecificos": {
            "recomendacao": "Posicione servidores SSH em DMZ ou redes de gerenciamento, exija conexão VPN para acesso e use controle de acesso à rede.",
            "comoImplementar": [
                "Desenhe estratégia de segmentação",
                "Implemente infraestrutura VPN",
                "Configure regras de firewall entre segmentos",
                "Configure NAC (Network Access Control)",
                "Monitore tráfego entre segmentos"
            ],
            "designRede": {
                "gerenciamento": "VLAN/subnet dedicada",
                "dmz": "DMZ para servidores acessíveis externamente",
                "vpn": "Gateway VPN para acesso remoto",
                "monitoramento": "Rede de monitoramento separada"
            },
            "comandos": [
                "# Exemplo configuração VLAN:",
                "# VLAN Gerenciamento: 192.168.100.0/24",
                "# VLAN DMZ: 192.168.200.0/24",
                "# Pool VPN: 10.8.0.0/24",
                "# Regras firewall (exemplo iptables):",
                "iptables -A INPUT -s 10.8.0.0/24 -p tcp --dport 22 -j ACCEPT",
                "iptables -A INPUT -s 192.168.100.0/24 -p tcp --dport 22 -j ACCEPT",
                "iptables -A INPUT -p tcp --dport 22 -j DROP"
            ]
        },
        "fontes": [
            "Guia de Arquitetura de Segurança de Rede",
            "Boas Práticas de Implementação VPN",
            "Princípios Zero Trust Network"
        ]
    }
]
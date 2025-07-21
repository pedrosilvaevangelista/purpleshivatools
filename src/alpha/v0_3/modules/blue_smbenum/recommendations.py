# recommendations

recommendations = [
    {
        "id": 1,
        "title": "Desabilitar Sessões Nulas SMB/NetBIOS",
        "severity": "Alta",
        "contexto": "Sessões nulas permitem acesso anônimo sem credenciais",
        "description": "Bloquear acesso anônimo aos compartilhamentos SMB",
        "specificDetails": {
            "passos_prioritarios": [
                "1. Verificar configuração atual:",
                "   - Windows: 'net share' para listar compartilhamentos",
                "   - Linux: 'smbstatus' para verificar sessões",
                "2. Desabilitar sessões nulas:",
                "   - Windows: Política de Grupo > 'Network access: Allow anonymous SID/name translation' = Disabled",
                "   - Linux Samba: adicionar 'restrict anonymous = 2' em smb.conf",
                "3. Reiniciar serviços SMB após alterações"
            ],
            "exemplos_praticos": {
                "Windows Server": [
                    "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous = 2",
                    "Ou via GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies"
                ],
                "Linux Samba": [
                    "Editar /etc/samba/smb.conf:",
                    "[global]",
                    "restrict anonymous = 2",
                    "guest account = nobody",
                    "map to guest = never"
                ]
            },
            "validacao": [
                "Testar com: 'smbclient -L <ip> -N'",
                "Deve retornar erro de acesso negado",
                "Verificar logs: tail -f /var/log/samba/log.*"
            ]
        },
        "sources": ["NIST SP 800-45", "CIS Controls"]
    },
    {
        "id": 2,
        "title": "Habilitar Assinatura SMB Obrigatória",
        "severity": "Média",
        "contexto": "Previne ataques man-in-the-middle e relay",
        "description": "Tornar assinatura digital obrigatória em comunicações SMB",
        "specificDetails": {
            "passos_prioritarios": [
                "1. Verificar suporte à assinatura atual",
                "2. Habilitar assinatura obrigatória no servidor",
                "3. Configurar clientes para exigir assinatura",
                "4. Testar compatibilidade com aplicações"
            ],
            "exemplos_praticos": {
                "Windows": [
                    "GPO: 'Microsoft network server: Digitally sign communications (always)' = Enabled",
                    "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\lanmanserver\\parameters\\RequireSecuritySignature = 1"
                ],
                "Linux Samba": [
                    "smb.conf: server signing = mandatory",
                    "smb.conf: client signing = mandatory"
                ]
            },
            "validacao": [
                "Verificar com Wireshark se tráfego está assinado",
                "Testar conectividade após mudanças"
            ]
        },
        "sources": ["Microsoft Security Baseline", "SANS"]
    },
    {
        "id": 3,
        "title": "Restringir Compartilhamentos Administrativos",
        "severity": "Alta",
        "contexto": "Compartilhamentos padrão podem expor sistema",
        "description": "Desabilitar ou restringir C$, ADMIN$, IPC$",
        "specificDetails": {
            "passos_prioritarios": [
                "1. Auditar compartilhamentos existentes: 'net share'",
                "2. Avaliar necessidade de cada compartilhamento",
                "3. Remover compartilhamentos desnecessários",
                "4. Aplicar ACLs restritivas nos necessários"
            ],
            "exemplos_praticos": {
                "Remover compartilhamentos": [
                    "net share C$ /delete",
                    "net share ADMIN$ /delete",
                    "Ou via Registry: AutoShareWks = 0"
                ],
                "Restringir IPC$": [
                    "Limitar acesso apenas a usuários autorizados",
                    "Configurar firewall para bloquear portas 139/445 externamente"
                ]
            },
            "validacao": [
                "Verificar lista: 'net share'",
                "Testar acesso remoto após mudanças"
            ]
        },
        "sources": ["OWASP", "Microsoft Hardening Guide"]
    },
    {
        "id": 4,
        "title": "Implementar Segmentação de Rede",
        "severity": "Média",
        "contexto": "Limitar propagação lateral em caso de comprometimento",
        "description": "Isolar serviços SMB em VLANs específicas",
        "specificDetails": {
            "passos_prioritarios": [
                "1. Mapear todos os serviços SMB na rede",
                "2. Criar VLANs dedicadas para file servers",
                "3. Implementar ACLs entre VLANs",
                "4. Configurar firewall interno"
            ],
            "exemplos_praticos": {
                "Firewall rules": [
                    "Bloquear 139/445 entre VLANs desnecessárias",
                    "Permitir apenas tráfego autorizado",
                    "Log de tentativas de acesso"
                ],
                "Monitoramento": [
                    "SIEM para detectar scans SMB",
                    "Alertas para conexões anômalas"
                ]
            },
            "validacao": [
                "Testar conectividade entre VLANs",
                "Verificar logs de firewall"
            ]
        },
        "sources": ["NIST Cybersecurity Framework", "SANS"]
    },
    {
        "id": 5,
        "title": "Atualizar Protocolos SMB Legados",
        "severity": "Alta",
        "contexto": "SMBv1 possui vulnerabilidades conhecidas",
        "description": "Desabilitar SMBv1 e usar apenas SMBv2/v3",
        "specificDetails": {
            "passos_prioritarios": [
                "1. Auditar versões SMB em uso na rede",
                "2. Identificar dependências de SMBv1",
                "3. Migrar aplicações para SMBv2/v3",
                "4. Desabilitar SMBv1 completamente"
            ],
            "exemplos_praticos": {
                "Windows": [
                    "PowerShell: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
                    "Ou via Programs and Features > Turn Windows features on/off"
                ],
                "Linux": [
                    "smb.conf: min protocol = SMB2",
                    "smb.conf: max protocol = SMB3"
                ]
            },
            "validacao": [
                "Verificar com: 'Get-SmbServerConfiguration | Select EnableSMB1Protocol'",
                "Testar aplicações críticas após mudança"
            ]
        },
        "sources": ["Microsoft Security Advisory", "CVE Database"]
    }
]
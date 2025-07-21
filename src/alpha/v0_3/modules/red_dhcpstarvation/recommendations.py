# recommendations.py
recommendations = [
    {
        "id": 1,
        "title": "Implementar DHCP Snooping",
        "severity": "Crítica",
        "contexto": "Proteção contra ataques DHCP Starvation",
        "description": "Configurar DHCP Snooping em switches para filtrar tráfego DHCP malicioso",
        "specificDetails": {
            "passos_prioritarios": [
                "1. Ativar DHCP Snooping globalmente no switch",
                "2. Configurar portas confiáveis (trusted) para servidores DHCP",
                "3. Definir limite de taxa para portas não confiáveis",
                "4. Habilitar validação de Option-82"
            ],
            "exemplos_praticos": {
                "Cisco Switch": [
                    "ip dhcp snooping",
                    "ip dhcp snooping vlan 1-100",
                    "interface GigabitEthernet0/1",
                    "ip dhcp snooping trust",
                    "ip dhcp snooping limit rate 5"
                ],
                "HP/Aruba Switch": [
                    "dhcp-snooping",
                    "dhcp-snooping vlan 1-100",
                    "interface 1",
                    "dhcp-snooping trust",
                    "dhcp-snooping max-bindings 5"
                ]
            },
            "validacao": [
                "show ip dhcp snooping",
                "show ip dhcp snooping binding",
                "Testar com cliente legítimo após implementação"
            ]
        },
        "sources": ["RFC 3046", "NIST SP 800-48"]
    },
    {
        "id": 2,
        "title": "Configurar Rate Limiting DHCP",
        "severity": "Alta",
        "contexto": "Limitar taxa de requisições DHCP por porta/cliente",
        "description": "Implementar limitação de taxa para prevenir flooding DHCP",
        "specificDetails": {
            "passos_prioritarios": [
                "1. Configurar limite de pacotes DHCP por segundo",
                "2. Definir ação quando limite for excedido",
                "3. Implementar logging de violações",
                "4. Configurar recuperação automática"
            ],
            "exemplos_praticos": {
                "Servidor ISC DHCP": [
                    "# dhcpd.conf",
                    "class 'rate-limit' {",
                    "  match if binary-to-ascii(16, 8, ':', substring(hardware, 1, 6)) = 'aa:bb:cc:dd:ee:ff';",
                    "  deny booting;",
                    "}"
                ],
                "Router Cisco": [
                    "access-list 100 permit udp any any eq bootps",
                    "class-map match-all DHCP-TRAFFIC",
                    "match access-group 100",
                    "policy-map RATE-LIMIT-DHCP",
                    "class DHCP-TRAFFIC",
                    "police 8000 conform-action transmit exceed-action drop"
                ]
            },
            "validacao": [
                "Monitorar logs de rate limiting",
                "Verificar contadores de drop",
                "Testar com carga normal vs anômala"
            ]
        },
        "sources": ["RFC 2131", "CISCO Security Guidelines"]
    },
    {
        "id": 3,
        "title": "Monitoramento de MAC Address Spoofing",
        "severity": "Média",
        "contexto": "Detectar padrões anômalos de MAC addresses",
        "description": "Implementar detecção de spoofing e padrões suspeitos de MAC",
        "specificDetails": {
            "passos_prioritarios": [
                "1. Configurar alertas para novos MAC addresses",
                "2. Implementar whitelist de MAC conhecidos",
                "3. Detectar padrões sequenciais ou aleatórios",
                "4. Integrar com SIEM para correlação"
            ],
            "exemplos_praticos": {
                "Script Python": [
                    "import re",
                    "def detect_sequential_mac(mac_list):",
                    "    # Detectar MACs sequenciais ou padrões suspeitos",
                    "    for i in range(len(mac_list)-1):",
                    "        if is_sequential(mac_list[i], mac_list[i+1]):",
                    "            return True"
                ],
                "Splunk Query": [
                    "sourcetype=dhcp_logs",
                    "| stats count by client_mac",
                    "| where count > 10",
                    "| eval suspicious=if(match(client_mac, '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'), 'yes', 'no')"
                ]
            },
            "validacao": [
                "Revisar logs de detecção",
                "Analisar falsos positivos",
                "Ajustar thresholds conforme necessário"
            ]
        },
        "sources": ["IEEE 802.3", "SANS Guidelines"]
    },
    {
        "id": 4,
        "title": "Segmentação de Rede DHCP",
        "severity": "Média",
        "contexto": "Isolar tráfego DHCP por segmentos",
        "description": "Separar redes em VLANs com servidores DHCP dedicados",
        "specificDetails": {
            "passos_prioritarios": [
                "1. Criar VLANs específicas por tipo de dispositivo",
                "2. Configurar servidor DHCP por VLAN",
                "3. Implementar DHCP relay agents",
                "4. Configurar ACLs entre VLANs"
            ],
            "exemplos_praticos": {
                "Configuração VLAN": [
                    "vlan 10",
                    "name CORPORATE",
                    "vlan 20",
                    "name GUEST",
                    "vlan 30",
                    "name IOT"
                ],
                "DHCP Pools separados": [
                    "ip dhcp pool CORPORATE",
                    "network 192.168.10.0 255.255.255.0",
                    "default-router 192.168.10.1",
                    "ip dhcp pool GUEST",
                    "network 192.168.20.0 255.255.255.0",
                    "default-router 192.168.20.1"
                ]
            },
            "validacao": [
                "Verificar isolamento entre VLANs",
                "Testar DHCP relay functionality",
                "Confirmar políticas de acesso"
            ]
        },
        "sources": ["RFC 3046", "VLAN Best Practices"]
    }
]
# recommendations.py (Corrigido para ARP Poison)
recommendations = [
    {
        "id": 1,
        "title": "Implementar Proteção contra ARP Spoofing",
        "severity": "Crítica",
        "contexto": "Baseado no ataque ARP Poisoning realizado",
        "description": "Implementar medidas para detectar e prevenir ataques ARP",
        "specificDetails": {
            "passos_prioritarios": [
                "1. Configurar ARP estático para hosts críticos",
                "2. Implementar monitoramento de mudanças na tabela ARP",
                "3. Configurar DHCP Snooping em switches gerenciados",
                "4. Habilitar Dynamic ARP Inspection (DAI) em switches"
            ],
            "exemplos_praticos": {
                "Configurar ARP estático no Linux": [
                    "sudo arp -s 192.168.1.1 aa:bb:cc:dd:ee:ff",
                    "echo '192.168.1.1 aa:bb:cc:dd:ee:ff' >> /etc/ethers"
                ],
                "Monitorar tabela ARP": [
                    "while true; do arp -a > /tmp/arp_$(date +%s).log; sleep 60; done",
                    "arpwatch -i eth0 -f /var/log/arpwatch.log"
                ],
                "Configurar DAI em switch Cisco": [
                    "ip dhcp snooping",
                    "ip arp inspection vlan 1-100",
                    "interface range gi0/1-24",
                    "ip arp inspection trust"
                ]
            },
            "validacao": [
                "Verificar logs do arpwatch: 'tail -f /var/log/arpwatch.log'",
                "Testar conectividade após configurar ARP estático",
                "Monitorar switches para alertas DAI"
            ]
        },
        "sources": ["NIST SP 800-115", "OWASP Network Security"]
    },
    {
        "id": 2,
        "title": "Segmentação de Rede e VLANs",
        "severity": "Alta",
        "contexto": "Limitar o impacto de ataques man-in-the-middle",
        "description": "Implementar segmentação adequada da rede",
        "specificDetails": {
            "passos_prioritarios": [
                "1. Separar redes críticas em VLANs dedicadas",
                "2. Implementar ACLs entre VLANs",
                "3. Configurar Port Security em switches",
                "4. Implementar 802.1X para autenticação de hosts"
            ],
            "exemplos_praticos": {
                "Configurar VLAN básica": [
                    "vlan 10",
                    "name SERVERS",
                    "interface gi0/1",
                    "switchport access vlan 10"
                ],
                "Port Security": [
                    "interface gi0/1",
                    "switchport port-security",
                    "switchport port-security maximum 2",
                    "switchport port-security violation shutdown"
                ]
            }
        },
        "sources": ["Cisco Best Practices", "Network Security Guide"]
    },
    {
        "id": 3,
        "title": "Monitoramento e Detecção de Intrusão",
        "severity": "Alta",
        "contexto": "Detectar rapidamente ataques ARP em andamento",
        "description": "Implementar sistemas de detecção para ataques de rede",
        "specificDetails": {
            "passos_prioritarios": [
                "1. Instalar e configurar Suricata/Snort",
                "2. Configurar alertas para mudanças ARP suspeitas",
                "3. Implementar SIEM para correlação de eventos",
                "4. Criar scripts de monitoramento automático"
            ],
            "exemplos_praticos": {
                "Regra Suricata para ARP": [
                    'alert arp any any -> any any (msg:"ARP Spoofing Detected"; content:"|00 02|"; offset:6; depth:2; sid:1000001;)'
                ],
                "Script de monitoramento": [
                    "#!/bin/bash",
                    "arp -a | while read line; do",
                    "  echo \"$(date): $line\" >> /var/log/arp_monitor.log",
                    "done"
                ]
            }
        },
        "sources": ["Suricata Documentation", "Network Monitoring Best Practices"]
    }
]
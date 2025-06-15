recommendations = [
    {
        "id": 1,
        "title": "Proteção Contra ARP Spoofing",
        "severity": "Crítica",
        "contexto": "Baseado na detecção de atividade de ARP spoofing",
        "description": "Implementar medidas de proteção contra ataques ARP spoofing",
        "specificDetails": {
            "passos_prioritarios": [
                "1. Implementar ARP table estática para hosts críticos:",
                "   sudo arp -s <ip_critico> <mac_critico>",
                "2. Configurar monitoramento ARP:",
                "   sudo apt install arpwatch",
                "   sudo systemctl enable arpwatch",
                "3. Implementar DHCP snooping em switches gerenciados"
            ],
            "exemplos_praticos": {
                "Configuração de ARP estático": [
                    "arp -s 192.168.1.1 aa:bb:cc:dd:ee:ff",
                    "echo '192.168.1.1 aa:bb:cc:dd:ee:ff' >> /etc/ethers"
                ],
                "Monitoramento com tcpdump": [
                    "sudo tcpdump -i eth0 arp",
                    "arpspoof -i eth0 -t 192.168.1.100 192.168.1.1"
                ]
            },
            "validacao": [
                "Verificar tabela ARP: 'arp -a'",
                "Monitorar logs: 'sudo tail -f /var/log/arpwatch.log'"
            ]
        },
        "sources": ["NIST SP 800-115", "OWASP Network Security"]
    },
    {
        "id": 2,
        "title": "Segmentação de Rede",
        "severity": "Alta",
        "contexto": "Prevenção de ataques man-in-the-middle",
        "description": "Implementar segmentação de rede para reduzir impacto de ataques",
        "specificDetails": {
            "passos_prioritarios": [
                "1. Implementar VLANs para separar tráfego:",
                "2. Configurar port security em switches:",
                "3. Implementar 802.1X para autenticação de porta"
            ],
            "exemplos_praticos": {
                "Configuração VLAN básica": [
                    "vlan 10 name ADMIN",
                    "vlan 20 name USERS", 
                    "interface fastethernet0/1",
                    "switchport access vlan 10"
                ]
            }
        },
        "sources": ["IEEE 802.1Q", "SANS Network Security"]
    },
    {
        "id": 3,
        "title": "Detecção de Anomalias de Rede",
        "severity": "Média",
        "contexto": "Monitoramento contínuo da rede",
        "description": "Implementar sistema de detecção de anomalias na rede",
        "specificDetails": {
            "passos_prioritarios": [
                "1. Instalar IDS/IPS (Suricata, Snort):",
                "2. Configurar alertas para mudanças na tabela ARP:",
                "3. Implementar baseline de tráfego normal"
            ]
        },
        "sources": ["NIST Cybersecurity Framework"]
    }
]
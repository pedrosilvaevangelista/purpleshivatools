recommendations = [
    {
        "id": "1",
        "title": "Verificação de dispositivos fora da sub-rede",
        "description": "Se um dispositivo ativo for detectado fora da faixa de IP esperada (CIDR ou range), isso pode indicar spoofing ou presença de um host não autorizado infiltrado na rede.",
        "mitre": ["T1040", "T0856"],
        "cve": [],
        "recommendation": "Em caso de detecção de hosts fora da sub-rede esperada, deve-se isolar esses dispositivos, investigar logs de DHCP, e realizar análise forense de tráfego suspeito (como ARP poisoning ou ARP spoofing)."
    },
    {
        "id": "2",
        "title": "MACs não resolvidos ou ausentes (N/A)",
        "description": "Hosts com MAC address como 'N/A' podem indicar uso de técnicas de evasão ou sistemas que respondem ao ping mas bloqueiam requisições ARP. Isso pode ser sintoma de sniffers passivos ou hosts ocultos.",
        "mitre": ["T1200"],
        "cve": [],
        "recommendation": "Deve-se verificar esses IPs com ferramentas de escaneamento em camada 3 e buscar por inconsistências com a tabela ARP. Considere coletar tráfego com tcpdump para análise posterior."
    },
    {
        "id": "3",
        "title": "Detecção de honeypots ou dispositivos falsos",
        "description": "Dispositivos que respondem a ARP/ping com alta consistência e latência extremamente baixa, ou que apresentam MACs comuns a VMs (como VMware, VirtualBox), podem ser honeypots ou armadilhas de detecção.",
        "mitre": ["T1589.002"],
        "cve": [],
        "recommendation": "Em caso de suspeita, deve-se realizar fingerprinting ativo com Nmap, validar serviços expostos e cruzar com logs históricos. Honeypots geralmente têm padrões de resposta não-humanos e ausência de navegação/atividade."
    },
    {
        "id": "4",
        "title": "Dispositivos com fabricantes genéricos ou desconhecidos",
        "description": "MACs com OUI não resolvido indicam dispositivos fora de padrões comerciais ou mascaramento de origem real. Pode representar hardware clonado, ataques man-in-the-middle ou testes de penetração não autorizados.",
        "mitre": ["T1040"],
        "cve": [],
        "recommendation": "Recomenda-se bloquear o acesso à rede desses dispositivos até que a origem seja validada. Pode-se usar NAC (Network Access Control) para forçar autenticação ou segmentar a rede para mitigar riscos."
    },
    {
        "id": "5",
        "title": "Hosts que aparecem e desaparecem em escaneamentos sucessivos",
        "description": "Oscilações no resultado de ARP Scan podem sugerir presença de sniffers passivos que ativam interfaces somente quando necessário (modo stealth) ou dispositivos configurados para não responderem consistentemente.",
        "mitre": ["T1140", "T1200"],
        "cve": [],
        "recommendation": "Use detecção de mudança em tempo real (com ferramentas como ARPWatch) e monitore alterações nos mapeamentos ARP. Crie alertas para qualquer novo host que aparece com um MAC desconhecido."
    },
    {
        "id": "6",
        "title": "MACs duplicados na rede",
        "description": "A presença de mais de um IP associado a um mesmo MAC, ou o mesmo MAC sendo visto em locais diferentes, pode indicar spoofing ARP ou conflitos de hardware em bridge mode.",
        "mitre": ["T1557.002"],
        "cve": [],
        "recommendation": "Identifique os switches onde esses hosts estão conectados, colete os logs de ARP e compare com a tabela CAM dos switches. A análise do histórico pode revelar conflitos ou ataque ativo."
    },
    {
        "id": "7",
        "title": "Dispositivos com MACs de máquinas virtuais em segmentos inesperados",
        "description": "Se dispositivos com MACs de VirtualBox, VMware ou QEMU estiverem presentes fora de ambientes de laboratório/teste, isso pode indicar máquinas virtuais não autorizadas ou testes de penetração maliciosos.",
        "mitre": ["T1564.006"],
        "cve": [],
        "recommendation": "Em redes produtivas, deve-se mapear quais segmentos permitem VMs. Qualquer MAC virtual em ambiente externo a isso deve ser isolado e auditado."
    }
]

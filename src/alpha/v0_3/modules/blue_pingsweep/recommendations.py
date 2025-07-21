recommendations = [
    {
        "id": "1",
        "title": "Bloqueio e filtragem de ICMP desnecessário",
        "description": (
            "Permitir apenas o tráfego ICMP estritamente necessário (ex.: Echo Reply para diagnosticar rede interna) "
            "para evitar que scanners externos descubram hosts ativos na rede."
        ),
        "mitre": ["T1040"], 
        "cve": [],
        "recommendation": (
            "Configure firewalls e roteadores para bloquear ICMP Echo Requests provenientes de redes externas "
            "e limitar respostas ICMP dentro da rede a segmentos confiáveis."
        )
    },
    {
        "id": "2",
        "title": "Monitoramento de tráfego ICMP anômalo",
        "description": (
            "Tráfego ICMP em volumes anormais ou fora de horários esperados pode indicar scans ou tentativas de reconhecimento."
        ),
        "mitre": ["T1040"],
        "cve": [],
        "recommendation": (
            "Implemente sistemas de detecção de intrusão (IDS) e monitoramento de rede para alertar sobre picos incomuns "
            "de pacotes ICMP ou varreduras sequenciais, correlacionando com logs e outras fontes."
        )
    },
    {
        "id": "3",
        "title": "Segmentação de rede e uso de VLANs",
        "description": (
            "Separar segmentos da rede em VLANs distintas limita o escopo de varreduras internas e dificulta movimentação lateral."
        ),
        "mitre": ["T1075"],
        "cve": [],
        "recommendation": (
            "Projete e implemente segmentação rígida da rede, usando VLANs para separar setores e aplicando políticas de acesso restrito."
        )
    },
    {
        "id": "4",
        "title": "Inventário ativo e baseline da rede",
        "description": (
            "Manter inventário atualizado dos dispositivos e um baseline de comportamento normal ajuda a identificar hosts ou padrões suspeitos."
        ),
        "mitre": ["T1087"], 
        "cve": [],
        "recommendation": (
            "Realize varreduras regulares e crie perfis de comportamento para identificar novos dispositivos, respostas ICMP inesperadas e mudanças no padrão de rede."
        )
    },
    {
        "id": "5",
        "title": "Restrições a resposta ICMP em endpoints críticos",
        "description": (
            "Hosts críticos (servidores, dispositivos de segurança) não devem responder a requisições ICMP, evitando exposição."
        ),
        "mitre": ["T1040"],
        "cve": [],
        "recommendation": (
            "Configure firewalls locais e sistemas operacionais para bloquear respostas ICMP em hosts sensíveis, reduzindo superfície de reconhecimento."
        )
    },
    {
        "id": "6",
        "title": "Auditoria e correlação de logs de rede",
        "description": (
            "Logs de firewalls, roteadores e IDS são cruciais para detectar varreduras e atividades suspeitas."
        ),
        "mitre": ["T1078"],
        "cve": [],
        "recommendation": (
            "Implemente correlação de logs com soluções SIEM, focando em padrões de varredura ICMP, alertas de repetição de pacotes e respostas anômalas."
        )
    }
]

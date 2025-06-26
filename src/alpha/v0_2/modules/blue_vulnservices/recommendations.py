recommendations = [
    {
        "id": "1",
        "title": "Validação de versões dos serviços em execução",
        "description": "Serviços com versões desatualizadas podem conter vulnerabilidades conhecidas exploráveis remotamente, especialmente quando expostos à internet.",
        "mitre": ["T1190", "T1210"],
        "cve": [],
        "recommendation": "Recomenda-se manter um inventário atualizado das versões em uso e realizar verificações periódicas de atualizações fornecidas pelo fabricante. Políticas de patch management automatizadas devem ser consideradas."
    },
    {
        "id": "2",
        "title": "Exposição de serviços em interfaces desnecessárias",
        "description": "Serviços que escutam em múltiplas interfaces (como internas e externas simultaneamente) aumentam a superfície de ataque, mesmo que sejam legítimos.",
        "mitre": ["T1133"],
        "cve": [],
        "recommendation": "Sempre que possível, limitar os serviços à interface estritamente necessária (ex: apenas localhost ou rede interna). Ferramentas como firewalls locais ou regras de iptables devem ser aplicadas para reduzir o alcance de exposição."
    },
    {
        "id": "3",
        "title": "Presença de serviços sem criptografia ou canal seguro",
        "description": "A ausência de TLS/SSL em serviços que transmitem dados sensíveis pode permitir interceptações e manipulações de tráfego.",
        "mitre": ["T1040", "T1557"],
        "cve": [],
        "recommendation": "Deve-se configurar SSL/TLS em todos os serviços compatíveis. Certificados digitais válidos e atualizados devem ser utilizados, preferencialmente de uma CA confiável. Protocolos inseguros devem ser desabilitados ou bloqueados."
    },
    {
        "id": "4",
        "title": "Serviços com autenticação fraca ou padrão",
        "description": "Muitos serviços são implantados com credenciais padrão ou sem autenticação adequada, o que facilita a movimentação lateral e acesso não autorizado.",
        "mitre": ["T1078", "T1110"],
        "cve": [],
        "recommendation": "Recomenda-se revisar todas as credenciais dos serviços expostos, remover contas padrão e aplicar políticas de senhas seguras. Autenticação multifator (MFA) deve ser aplicada sempre que possível."
    },
    {
        "id": "5",
        "title": "Banner ou fingerprinting exposto",
        "description": "Muitos serviços retornam informações sensíveis como nome, versão, sistema operacional ou frameworks em resposta a conexões simples.",
        "mitre": ["T1592", "T1082"],
        "cve": [],
        "recommendation": "Deve-se desabilitar banners e mensagens de erro informativas. Utilizar camadas de proxy reverso ou WAF pode ajudar a mitigar coleta automatizada de informações."
    },
    {
        "id": "6",
        "title": "Portas abertas não documentadas",
        "description": "A presença de serviços escutando em portas não documentadas pode ser sintoma de má configuração, software não autorizado ou comprometimento.",
        "mitre": ["T1046"],
        "cve": [],
        "recommendation": "Manter um mapeamento rigoroso das portas e serviços autorizados, realizar auditorias regulares de exposição, e aplicar segmentação de rede com firewalls ou ACLs."
    }
]

recommendations = [
    {
        "id": "1",
        "title": "Portas abertas sem necessidade operacional",
        "description": "A manutenção de portas abertas que não são utilizadas pode aumentar a superfície de ataque e servir de entrada para explorações futuras.",
        "mitre": ["T1046", "T1065"],
        "cve": [],
        "recommendation": "É recomendável desabilitar ou bloquear serviços desnecessários e fechar portas que não estejam em uso. O princípio do menor privilégio também deve ser aplicado à exposição de serviços."
    },
    {
        "id": "2",
        "title": "Serviços escutando em todas as interfaces",
        "description": "Quando um serviço escuta em 0.0.0.0 ou ::, ele fica acessível a partir de qualquer rede conectada ao host, incluindo redes externas não confiáveis.",
        "mitre": ["T1133"],
        "cve": [],
        "recommendation": "Sempre que possível, restrinja os serviços para escutarem apenas na interface necessária. Por exemplo, aplicações administrativas devem responder apenas a localhost ou rede interna."
    },
    {
        "id": "3",
        "title": "Identificação de portas comuns usadas em ataques",
        "description": "Portas como 21 (FTP), 23 (Telnet), 445 (SMB), e 3389 (RDP) são frequentemente alvos de ataques automatizados e tentativas de força bruta.",
        "mitre": ["T1110", "T1021"],
        "cve": [],
        "recommendation": "Caso serviços nessas portas sejam realmente necessários, devem ser protegidos com autenticação robusta, monitoramento contínuo, e, preferencialmente, encapsulados em VPNs ou com acesso segmentado."
    },
    {
        "id": "4",
        "title": "Presença de serviços desconhecidos",
        "description": "A abertura de portas que não estão documentadas pode indicar software não autorizado, backdoors ou testes não autorizados em produção.",
        "mitre": ["T1203", "T1046"],
        "cve": [],
        "recommendation": "Manter inventário atualizado de todos os serviços e portas permitidas. Serviços desconhecidos devem ser verificados com os responsáveis e, se for o caso, removidos ou bloqueados imediatamente."
    },
    {
        "id": "5",
        "title": "Falta de segmentação de rede",
        "description": "Serviços internos muitas vezes são acessíveis a toda a rede, aumentando o risco de movimentação lateral em caso de comprometimento.",
        "mitre": ["T1021", "T1563"],
        "cve": [],
        "recommendation": "Implemente segmentação de rede com VLANs, firewalls e listas de controle de acesso (ACLs) para limitar a comunicação entre segmentos de rede e expor apenas o necessário."
    },
    {
        "id": "6",
        "title": "Portas abertas em dispositivos de usuários finais",
        "description": "Dispositivos de usuários finais como estações de trabalho raramente precisam manter portas abertas, exceto em casos muito específicos (como compartilhamento local).",
        "mitre": ["T1071", "T1049"],
        "cve": [],
        "recommendation": "Auditorias periódicas devem ser realizadas para identificar e fechar portas abertas em dispositivos de endpoint. Firewalls locais devem ser configurados com regras restritivas por padrão."
    }
]

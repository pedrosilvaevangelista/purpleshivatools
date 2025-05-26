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
    }
]
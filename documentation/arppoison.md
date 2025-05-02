# ARP Poison DoS
Ferramenta de ataque de negação de serviço via envenenamento ARP, com restauração automática da rede e monitoramento de pacotes enviados e erros.

---

## ✨ Visão Geral
Este script realiza um ataque de ARP Poison (envenenamento de cache ARP) entre uma vítima e o gateway, resultando em interrupção da comunicação da vítima. </br>
O ataque é monitorado em tempo real, permite duração configurável e restaura a rede ao final da execução.

---

## ⚖️ Funcionalidades
- Envenenamento ARP contínuo entre alvo e gateway
- Suporte a execução interativa ou via linha de comando (CLI)
- Contador em tempo real de pacotes enviados e erros
- Controle automático de duração do ataque
- Restauração da tabela ARP da vítima e gateway ao término

---

## 📝 Requisitos
- Python 3.6+
- Permissões de root para envio de pacotes ARP

---

## Blibiotecas 
```bash
pip install scapy
```

---

# 🕹️ Como Usar 
```bash
sudo python3 red_arppoison.py
```

Você será solicitado a inserir: </br>
- IP da vítima
- IP do gateway
- Duração do ataque (em segundos)

Modo Terminal (CLI)
```bash
sudo python3 red_arppoison.py -t 192.168.0.105 -g 192.168.0.1 -d 60
```

Parâmetros: </br>
- -t, --target: IP do alvo 
- -g, --gateway: IP do gateway 
- -d, --duration: Duração do ataque em segundos (padrão 30s) 

---

## 🔎 O que o Script Faz
1. Verifica permissões de root
2. Inicia envio de pacotes ARP falsificados em dois sentidos (alvo ↔ gateway)
3. Monitora pacotes enviados, erros e tempo de execução
4. Permite finalização segura com Ctrl+C
5. Restaura as tabelas ARP da vítima e do gateway ao encerrar

---

## 📊 Exemplo de Execução

```bash
[*] ARP poison started: target=192.168.0.105, gateway=192.168.0.1, duration=60s
Packets Sent: 1020 | Errors: 0 | Duration: 59s
[*] Attack complete: Packets Sent=1040, Errors=0, Duration=60s

```

---

## ❌ Encerramento Seguro
- Tratamento de interrupção (Ctrl+C) seguro
- Logs e conexões são finalizados corretamente

---

## 🚀 Casos de Uso
- Testes de segurança em redes privadas
- Auditoria de serviços expostos
- Detecção de vulnerabilidades comuns em ambientes internos

---

## 📄 Licença
Ferramenta de uso educativo.
> ⚠️ Utilize apenas em sistemas que você tenha autorização para escanear.



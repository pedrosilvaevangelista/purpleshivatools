![Banner](bannerpurpleshivatools.jpg)

&nbsp;

# Purple Shiva Tools 🔱

Purple Shiva Tools é um conjunto de ferramentas voltado para atividades de pentest e operações ofensivas em segurança da informação. Seu principal objetivo é possibilitar testes de eficácia dos controles de segurança corporativos, podendo também ser utilizado com fins educacionais e laboratoriais.


## 🛠️ Funcionalidades

### **Port Scanner**
Realiza varreduras de portas em dispositivos da rede, identificando quais serviços estão ativos e em escuta.

### **ARP Network Scanner** 
Efetua a descoberta de dispositivos conectados à rede, coletando informações como nome de host, endereços IP, sistemas operacionais e suas respectivas versões.

### **Scanner de Vulnerabilidades**
Executa análises sobre os ativos da rede para identificar falhas de segurança conhecidas que possam ser exploradas.

### **ICMP Network Scanner**
Realiza descoberta de hosts ativos na rede utilizando protocolo ICMP.

### **ARP Network Spoof**
Executa ataques de spoofing ARP para interceptação e manipulação de tráfego de rede.

### **Enumeração SMB**
Coleta informações detalhadas do protocolo SMB em dispositivos da rede.

### **ARP Poison**
Ataque de negação de serviço que impede o processamento de requisições ARP.

### **DHCP Starvation**
Esgota os endereços IPs disponíveis no pool DHCP da rede.

## 📊 Relatórios

O Purple Shiva Tools possibilita a exportação de relatórios nos formatos **JSON** e **XML**, facilitando a análise e documentação dos resultados obtidos.

## 📋 Requisitos

- **Acesso à Internet**
- **Python 3**
- **Visual Studio Code** (preferencial)
- **Linux** (preferencialmente Kali Linux)
- **Git**

## ⚡ Instalação

> **Nota:** Execute como root

### 1. Clone o repositório
```bash
git clone -b alpha --single-branch https://github.com/PurpleShivaTeam/purpleshivatools.git
```

### 2. Abrir com Visual Studio Code (opcional)
```bash
code purpleshivatools --no-sandbox --user-data-dir
```
> **Obs:** Caso não tenha o Visual Studio Code, pule esta etapa

### 3. Configurar ambiente
```bash
cd src/alpha/v0_3/   
python3 -m venv venv 
source venv/bin/activate 
```

### 4. Instalar dependências
```bash
pip3 install -r requirements.txt
```

### 5. Executar a aplicação
```bash
python3 bootstrap.py
```

## ⚠️ Avisos Importantes

**🚧 PROJETO EM DESENVOLVIMENTO**

Este projeto encontra-se em fase de desenvolvimento ativo.

**⚖️ RESPONSABILIDADE DE USO**

Não nos responsabilizamos pelo mal uso da ferramenta. Use o Purple Shiva Tools **APENAS** em ambientes autorizados e para fins legítimos de teste de segurança.

## 📌 Versão

**Versão do Projeto:** Alpha V0.3

## Contribuições ✨

Contribuições de qualquer tipo são bem-vindas!

<a href="https://github.com/PurpleShivaTeam/purpleshivatools/graphs/contributors">
  <img src="https://contributors-img.web.app/image?repo=PurpleShivaTeam/purpleshivatools&max=100" alt="Lista de contribuidores" width="200" />
</a>

---

**Purple Shiva Team** - Desenvolvendo ferramentas para profissionais de segurança da informação.

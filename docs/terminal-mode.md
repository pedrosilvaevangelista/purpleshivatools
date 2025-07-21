# [PORTUGUÊS]
# COMO USAR O MODO TERMINAL

O modo terminal é basicamente uma linha de comando onde você pode executar comandos específicos com seus próprios parâmetros. Você também pode usá-lo para scripts.

## Exemplos práticos
> purplest-arpscan -i 192.168.0.0/24 -d 0.05 -t 3 --format xml --verbose

No exemplo acima, estamos tentando escanear a rede 192.168.0.1/24 usando arpscan. Também estamos especificando um delay de 0.05 segundos e um timeout de 3 segundos. Queremos que o relatório seja gerado em formato .XML e também queremos exibir o scan em tempo real na tela usando a opção verbose.

> purplest-pingsweep -i 192.168.0.0/24

No exemplo acima, estamos tentando escanear a rede 192.168.0.0/24 usando pingsweep. Não estamos especificando nenhum parâmetro, então serão usados os valores padrão.


# COMO INSTALAR NO LINUX (KALI)

Para a distribuição Kali Linux, você precisa:
1. Acessar a pasta /purpleshivatools/src/alpha/v0_2/
> cd /purpleshivatools/src/alpha/v0_2/

2. Executar o comando abaixo
> pip install --break-system-packages .

3. Agora o módulo purplest está instalado. Para acessar o menu principal, execute o comando abaixo
> purplest

4. Para ferramentas específicas como pingsweep, arpscan etc. você pode executar os seguintes comandos (ambos abrirão o menu interativo)
> purplest-pingsweep

> purplest-arpscan

5. Para o modo terminal, você precisa especificar os parâmetros. No exemplo abaixo usamos -h para obter ajuda de ambos os comandos
> purplest-pingsweep -h

> purplest-arpscan -h

## Se quiser desinstalar o purplest no Kali, execute o comando abaixo
> pip uninstall --break-system-packages purplest


# PARA OUTRAS DISTRIBUIÇÕES LINUX
Para outras distribuições Linux, você precisa:
1. Acessar a pasta /purpleshivatools/src/alpha/v0_2/
> cd /purpleshivatools/src/alpha/v0_2/

2. Executar o comando abaixo
> pip install .

3. Agora o módulo purplest está instalado. Para acessar o menu principal, execute o comando abaixo
> purplest

4. Para ferramentas específicas como pingsweep, arpscan etc. você pode executar os seguintes comandos (ambos abrirão o menu interativo)
> purplest-pingsweep

> purplest-arpscan

5. Para o modo terminal, você precisa especificar os parâmetros. No exemplo abaixo usamos -h para obter ajuda de ambos os comandos
> purplest-pingsweep -h

> purplest-arpscan -h

## Se quiser desinstalar o purplest em outras distribuições Linux, execute o comando abaixo
> pip uninstall purplest

-----------------------------------------------------------------------------------------------------------------------------------------

# [ENGLISH]
# HOW TO USE TERMINAL MODE

The terminal mode is basically a command line where you can run the specific command with its own parameters. You can also use it for scripts.

## Practice examples
> purplest-arpscan -i 192.168.0.0/24 -d 0.05 -t 3 --format xml --verbose
In the example above, we're trying to scan the 192.168.0.1/24 network using arpscan. We're also specifying the delay to 0.05 seconds and the timeout to 3 seconds. We want the report to be a .XML file and we also want to display the scan live on screen using the verbose option.

> purplest-pingsweep -i 192.168.0.0/24
In the example above, we`re trying to scan the 192.168.0.0/24 network using pingsweep. We are not specifying any parameters, so it will use the default values.


# HOW TO INSTALL ON LINUX (KALI)

For Kali linux distribution, you need to:
1. Go to the /purpleshivatools/src/alpha/v0_2/ folder
> cd /purpleshivatools/src/alpha/v0_2/

2. Run the command below
> pip install --break-system-packages .

3. Now the purplest module is installed. To access the main menu, run the command below
> purplest

4. For specific tools like pingsweep, arpscan etc. you can run the following commands (both will open the interactive menu)
> purplest-pingsweep

> purplest-arpscan

5. For the terminal mode, you need to specify the paramaters, in the example below we are using -h to get help from both commands
> purplest-pingsweep -h

> purplest-arpscan -h

## If you want to uninstall purplest on kali, you need to run the command below
> pip uninstall --break-system-packages purplest


# FOR OTHER LINUX DISTRIBUTIONS
For Kali linux distribution, you need to:
1. Go to the /purpleshivatools/src/alpha/v0_2/ folder
> cd /purpleshivatools/src/alpha/v0_2/

2. Run the command below
> pip install .

3. Now the purplest module is installed. To access the main menu, run the command below
> purplest

4. For specific tools like pingsweep, arpscan etc. you can run the following commands (both will open the interactive menu)
> purplest-pingsweep

> purplest-arpscan

5. For the terminal mode, you need to specify the paramaters, in the example below we are using -h to get help from both commands
> purplest-pingsweep -h

> purplest-arpscan -h

## If you want to uninstall purplest on other linux distributions, you need to run the command below
> pip uninstall purplest

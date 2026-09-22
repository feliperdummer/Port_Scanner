Port-Scanner - Python / Scapy

Esse escaneador de portas implementa de forma relativamente simples
protocolos de redes comuns, como TCP, UDP, ICMP, IP, ARP e Ethernet.

**Como rodar**

	O programa não roda em Windows nativamente, porque forja pacotes
	que estão abaixo da camada 3. Para utilizar o programa num am-
	biente windows, utilize WSL2.

`sudo python port_scan.py` *target_ip* *[porta(s)]* 



**Por que utilizar Scapy ?**

	A razao para utilizacao da lib Scapy foi inicialmente porque
	o Windows limita até que nivel eu posso manipular pacotes,
	mesmo com privilégios de admin. Além disso, a lib é usada 
	para realizar o escaneamento quando este é na própria má-
	quina.

**Implementação dos pacotes Ethernet, ARP, IP, ICMP e TCP**
	
	Apos os primeiros testes utilizando Scapy, eu percebi que ele
	faz o program ficar lento demais pra um escaneador de portas
	(que nesse caso ja fica lento por ser Python), entao a unica
	alternativa era que eu montasse os pacotes de forma manual. Os
	pacotes ARP e Ethernet foram os primeiros que eu implementei na
	mao porque por incrivel que pareca, eles sao os mais faceis de 
	implementar. Depois disso, vieram os pacotes ICMP, IP e o TCP.
	O módulo TCP foi pego na Web e usado como base para elaboração
	dos outros módulos que forjam pacotes da pilha TCP/IP.

**Mudanças futuras**

	A mudança que mais faria diferença agora é a implementação de
	multi-threading para que escaneamentos que testam varias por-
	tas e escaneamentos de rede não sejam tão demorados.

	Além disso, a quantidade de flags que são aceitadas como opções 
	de usuário hoje é muito limitada. Isso inclui apenas o endereço
	IP alvo e a quantidade de portas.


**Estrutura do projeto**

	Port_Scanner/
	├── extra/
	│   ├── .gitignore
	│   ├── flag_parser.py
	│	├── extra.py
	│   └── errors.py
	│
	├── network/
	│   ├── arp.py
	│   ├── ether.py
	│   ├── ip.py
	│   ├── tcp.py
	│   ├── icmp.py
	│   └── host_info.py
	│       
	│
	├── .gitignore
	├── scan.py
	└── README.md
Port-Scanner - Python / Scapy

Esse escaneador de portas implementa de forma relativamente simples
protocolos de redes comuns, como TCP, UDP, ICMP, IP, ARP e Ethernet.

**Como rodar**

	Pelo fato do programa forjar pacotes, ele roda apenas em distros Linux.

**`sudo python port_scan.py *target_ip* *[porta(s)]*`** 



**Por que utilizar Scapy ?**

	A razao para utilizacao da lib Scapy foi inicialmente porque
	o Windows limita ate que nivel eu posso manipular pacotes,
	mesmo com privilegios de admin, e tambem pra conseguir fazer
	o projeto funcionar antes de qualquer mudanca mais drastica.

**Implementacao dos pacotes ARP e Ethernet**
	
	Apos os primeiros testes utilizando Scapy, eu percebi que ele
	faz o program ficar lento demais pra um escaneador de portas
	(que nesse caso ja fica lento por ser Python), entao a unica
	alternativa era que eu montasse os pacotes de forma manual. Os
	pacotes ARP e Ethernet foram os primeiros que eu implementei na
	mao porque por incrivel que pareca, eles sao os mais faceis de 
	implementar.

**Mudancas futuras**

	O principal objetivo agora e terminar de montar os pacotes dos outros
	protocolos de rede (TCP, UDP, ICMP) pra reduzir mais ainda a dependencia
	de outras bibliotecas e melhorar a performance do programa. Alem disso, 
	implementacoes como suporte para enderecos do tipo IPv6 e uma range de 
	flags maior tambem estao na fila

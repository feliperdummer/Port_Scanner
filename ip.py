import struct, socket, array

# Pra comecar, essa classe vai ser um pouco mais completa
# que as outras que fiz para o resto dos protocolos, com o
# intuito de fazer algumas operacoes de desempacotar paco-
# tes e verificar campos especificos destes

# A classe vai instanciar um header IP, que por sua vez pode usar
# o metodo build() para transformar esse header em uma sequencia de
# bytes que pode ser enviado pelo internet

# Eu vou tentar deixar o menos de especificacao possivel pro usuario passar
# como argumento do construtor, pra que essa abstracao fique toda dentro da 
# classe. O mais importante e saber se o protocolo da camada de transporte e
# TCP ou UDP, e obviamente qual o IP da fonte e qual o IP do destino

# Esquece o que eu disse antes, nao vai vir cacete nenhum de pacote de outra
# camada, apenas o usuario tem que especificar qual o tipo do header de cima
# atraves do campo protocol e tambem o tamaho medido em bytes do pacote da ca-
# mada superior. Eu vou deixar pra juntar o pacote IP com o pacote da camada 
# superior quando eu tiver perto de mandar o pacote, na funcao try_syn_scan()

def chksum(packet: bytes) -> int:
    if len(packet) % 2 != 0:
        packet += b'\0'

    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16

    return (~res) & 0xffff

class IP:
	def __init__(self, 
				protocol: 		 int,
				upper_pack_size: int,
				src_addr: 		 str,
				dst_addr: 		 str):
	   self.protocol = protocol
	   self.upper_pack_size = upper_pack_size
	   self.src_addr = src_addr
	   self.dst_addr = dst_addr

	def build(self):
		version = 4 # versao do protocolo, IPv4
		ihl = 5 # tamanho do header, equivale a 5 palavras de 32bits, 20 bytes
		version_ihl = (version << 4) | ihl
		type_of_service = 0 # aqui seria a qualidade do servico, 0 e padrao
		total_length = ihl + self.upper_pack_size
		identification = 69 # numero aleatorio 
		flags = 2 # 010 -> reserved, Don't fragment, Last fragment
		frag_offset = 0 # primeiro (e ultimo) fragmento sempre e 0
		flags_frag_offset = (flags << 13) | frag_offset
		ttl = 127
		# protocolo deve ter valor 6 para tcp
		
		# header provisorio para calcular o check_sum
		header = struct.pack(
			'!BBHHHBBH4s4s',
			version_ihl, 	   type_of_service, 	 		   total_length,
			identification, 							  flags_frag_offset, 
			ttl, 				self.protocol, 				    		  0,
			socket.inet_aton(self.src_addr), socket.inet_aton(self.dst_addr)
		)

		print(header) # apagar aqui

		checksum = chksum(header)

		# substitui o checksum provisorio com o real
		header = header[:10] + struct.pack('H', checksum) + header[12:]

		return header

ip_packet = IP(6, 40, '192.168.3.13', '192.168.3.15').build()
print(ip_packet)
print(len(ip_packet))


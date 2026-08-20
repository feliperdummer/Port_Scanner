import struct, socket, array, tcp

from socket import inet_aton, inet_ntoa

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

# So pra fixar, o intuito dessa classe e o seguinte:
# 	Construir e devolver pacotes IP em formate de bytes prontos
#	para envio na rede
#
#	Interpretar pacotes do tipo IP, onde a camada mais baixa do pacote e a 
#	propria camada de rede. O metodo em especifico que criei ate o momento
#	espera receber um pacote que comeca na camada 3 (as camadas inferiores
#	ja foram retiradas pelo sistema operacional) e desse pacote ele extrai
#	o header IP, o transforma em uma tupla de 12 campos que representam os
# 	campos do cabecalho IP ate Destination Address, e por ultimo devolve 
#	uma outra tupla que tem como elementos essa tupla do cabecalho IP e o
#	resto dos bytes em formato bruto que restaram do pacote (pode ser 0)



#	via: https://datatracker.ietf.org/doc/html/rfc791#ref-9
#
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |Version|  IHL  |Type of Service|          Total Length         |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |         Identification        |Flags|      Fragment Offset    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  Time to Live |    Protocol   |         Header Checksum       |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                       Source Address                          |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                    Destination Address                        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                    Options                    |    Padding    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#
#	Version: Versao do protocolo IP, nesse caso, IPv4
#
#	IHL: Internet Header Length, tamanho em palavras de 4 bytes (32 bits)
#		 do header. O valor minimo e 5, que equivale a 20 bytes
#
#	Type Of Service: Qualidade do servico desejada, o padrao e 0
#
#	Total Length: Tamanho total do pacote, incluindo header e payload de 
#			  	  camadas superiores. Esse valor e medido em bytes, entao
#				  quando for passar para o construtor, passe em BYTES.
#
#	Identification: Valor que ajuda a juntar os fragmentos de um datagrama
#				  	quando este tem que ser fragmentado
#
#	Flags: Flags de controle
#
#	Fragment Offset: Indica o indice do fragmento atual no datagrama 
#
#	Time to Live: Quantidade de saltos que o pacote pode dar antes que seja
#				  dropado. Cada vez que ele da um salto (hop) (passa por um ro-
#				  teador), o ttl e decrementado por uma unidade
#
#	Protocol: Valor que indica o protocolo presente na camada acima
#
#	Header Checksum: Verificacao de integridade do pacote
#
# 	Source Address: Endereco IP da fonte
#
#	Destination Address: Endereco IP do destino
#
#	Options e Padding: Opcionais que nao sao muito comuns  


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
		version = 4
		ihl = 5
		version_ihl = (version << 4) | ihl
		type_of_service = 0
		total_length = ihl*4 + self.upper_pack_size
		identification = 69
		flags = 2
		frag_offset = 0
		flags_frag_offset = (flags << 13) | frag_offset
		ttl = 127
		
		# header provisorio para calcular o check_sum
		header = struct.pack(
			'!BBHHHBBH4s4s',
			version_ihl, 	   type_of_service, 	 		   total_length,
			identification, 							  flags_frag_offset, 
			ttl, 				self.protocol, 				    		  0,
			socket.inet_aton(self.src_addr), socket.inet_aton(self.dst_addr)
		)

		checksum = chksum(header)

		# substitui o checksum provisorio com o real
		header = header[:10] + struct.pack('H', checksum) + header[12:]

		return header

	def extract(packet: bytes):
		ihl = (packet[0] & 0x0F) * 4
		ip_header = struct.unpack('!BBHHHBBH4s4s', packet[:ihl])
		
		ip_header_good = (
			ip_header[0] >> 4,		   # Versao do protocolo IP
			(ip_header[0] & 0x0F) * 4, # Tamanho do header em bytes
			ip_header[1],			   # Tipo de servico
			ip_header[2],			   # Tamanho total do pacote
			ip_header[3],			   # Identificacao
			ip_header[4] >> 13,		   # Flags
			(ip_header[4] & 0x1FFF),   # Offset do fragmento
			ip_header[5], 			   # Time to Live
			ip_header[6],			   # Identificador do protocolo de cima
			ip_header[7],			   # Checksum do pacote
			inet_ntoa(ip_header[8]),   # Endereco IP fonte
			inet_ntoa(ip_header[9])	   # Endereco IP destino
		)

		return (ip_header_good, packet[ihl:])

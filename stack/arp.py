import struct, socket as s

#
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |         Hardware type         |       Protocol type (0x800)   |
# 	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   | Hard. Length  | Proto. Length |           Operation           |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                    Sender Hardware Address                    |
#   |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                               |    Sender Protocol Address... |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   | ...Sender Protocol Address    |    Target Hardware Address    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
#   |                                                               |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                    Target Protocol Address                    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#
#   Hardware Type: Indica o protocolo da camada de enlace. É um valor
#  				   inteiro e quando é 1, indica Ethernet. 16 bits
#
#	Protocol Type: Indica o protocolo de rede para o qual o ARP request
#				   é requisitado. Para IPv4, tem valor 0x800. 16 bits
#
#	Hardware Length: Tamanho em bytes do endereço físico (MAC). Para o
#                    Ethernet, o tamanho é 6. 8 bits
#
#	Protocol Length: Tamanho em bytes do endereço de rede. Para IPv4, o
#    				 tamanho é 4. 8 bits
#
#	Operation: Indica o tipo de operação realizada. 1->request, 2->reply.
#			   16 bits
#
#	Sender Hardware Address: Endereço MAC do remetente. No ARP request,
# 							 é usado para indicar o endereço do host
#							 que enviou o request. No ARP reply, é usado
#							 para indicar o enderço que o request estava
#							 buscando. Tem que ser bytes brutos. 48 bits
#
#	Sender Protocol Address: Endereço de rede do remetente. Tem que ser 
# 							 bytes brutos. 32 bits
#
#	Target Hardware Address: Endereço MAC do destinatário. No ARP request,
#							 o campo é ignorado. Tem que ser byte brutos. 
#             				 48 bits
#
#	Target Protocol Address: Endereço de rede do destinatário. Tem que ser
# 						     bytes brutos. 32 bits

class Arp:
	def __init__(self,
		htype,     ptype,
		hlen, plen, oper,
		sha,         spa,
		tha,         tpa):

		self.htype = htype
		self.ptype = ptype
		self.hlen  = hlen
		self.plen  = plen
		self.oper  = oper
		self.sha   = sha
		self.spa   = spa
		self.tha   = tha
		self.tpa   = tpa

	# monta o pacote usando struct, retorna o pacote montado
	def build(self):
		return struct.pack("!HHBBH6s4s6s4s",
			self.htype, self.ptype,
			self.hlen, self.plen, self.oper,
			bytes.fromhex(self.sha.replace(':', '')), s.inet_aton(self.spa),
			bytes.fromhex(self.tha.replace(':', '')), s.inet_aton(self.tpa))

	
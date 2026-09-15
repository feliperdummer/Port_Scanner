import struct, socket as s

# O Ethernet Frame II é composto por três partes. É
# composto pelo Header MAC, que contém o MAC Address de 
# destino, o MAC Address fonte e o EtherType. O Ethertype
# indica qual o protocolo da camada superior.
#
# 	Valores comuns para Ethertype:
#
#		IPv4 -> 0x800
#		IPv6 -> 0x86DD
#		ARP  -> 0x806
#
# Depois do Header MAC, vem o campo de dados, que contém o
# payload do frame Ethernet. O payload normalmente é com-
# posto pelos pacotes formados pelos protocolos das cama-
# superiores, IP, ARP, TCP, etc. Tem um tamanho minimo de 
# 46 bytes e um tamanho maximo de 1500 bytes
#
# A última parte do Ethernet Frame II é o CRC Checksum.   

# Header Ethernet II (O que a gente forja):
#
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                    Destination MAC Address				    |
#	|							    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#	|                               |       Source MAC Address      |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
#   |      														    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |           EtherType           |             Data...           |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                           	|
#   | 								                            	|
#
#
#	Destination MAC Address: Endereço MAC do destinatário do pacote.
#							 48 bits
#
#	Source MAC Address: Endereço MAC do remetente do pacote. 48 bits
#
#	EtherType: Protocolo da camada superior. 16 bits
#
#	Data: Payload do pacote, normalmente pacotes de camadas superiores.
#		  Tem no mínimo 46 bytes e no máximo 1500 bytes. Caso o pacote 
#		  da camada superior não tenha tamanho suficiente, basta aplicar
#		  o padding necessário. min 46 bytes max 1500 bytes
#
# "Ah mas e o preamble, SFD e FCS ?"
# 		A gente finge que não existe porque o SO cuida

class Ether:
	def __init__(self,
		dmac,           smac,
		ethertype, 		payload = None, 
		payload_size = 0):
		self.dmac = dmac
		self.smac = smac
		self.ethertype = ethertype
		self.payload = payload
		self.payload_size = payload_size

	def build(self):
		packet = struct.pack("!6s6sH",
			bytes.fromhex(self.dmac.replace(':', '')), 
			bytes.fromhex(self.smac.replace(':', '')), 
			self.ethertype)

		if self.payload_size < 46:
			self.payload += (b"\x00" * (46 - self.payload_size))
		elif payload > 1500:
			print('ether.py: payload too big (>1500 bytes)')
			return

		packet += self.payload

		return packet

	def extract(frame: bytes):
		ether_header = struct.unpack("!6s6sH", frame[:14])
		return (ether_header, frame[14:])
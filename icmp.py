import socket, struct, array, ip

# via: https://datatracker.ietf.org/doc/html/rfc792
#
# Echo or Echo Reply Message
#
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |     Type      |     Code      |          Checksum             |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |           Identifier          |        Sequence Number        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |     Data ...
#   +-+-+-+-+-
#
#	Type: 8 -> echo; 0 -> echo reply
#
#	Code: 0
#
#	Checksum: Controle de integridade do pacote
#
#	Identifier: Caso o code seja 0, e um identificador que ajuda a combinar
#				echos e echo replies. 
#
#	Sequence Number: Caso o code seja 0, e um identificador que ajuda a combi-
#					 nar echos e echo replies. 
#
# 	Data: Dados que sao enviados em um echo tem que ser enviados de volta no 
#		  reply.

def chksum(packet: bytes) -> int:
    if len(packet) % 2 != 0:
        packet += b'\0'

    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16

    return (~res) & 0xffff

class Echo:
	def __init__(self,
				type: int,
				data: int):
		self.type = type
		self.data = data

	def build(self):
		header = struct.pack(
			'!BBHHHI',
			self.type, 0x00, 0x0000,
			0x00000001,  0x00000001,
			self.data
		)

		checksum = chksum(header)

		header = header[:2] + struct.pack('H', checksum) + header[4:]

		return header

	def extract(packet: bytes):
		icmp_header = struct.unpack('!BBHHHI', packet)
		return icmp_header
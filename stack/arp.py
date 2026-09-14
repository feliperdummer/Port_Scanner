import struct, socket as s

class Arp:
	def __init__(self,
		htype_16bit, ptype_16bit,
		hlen_8bit, plen_8bit, oper_16bit,
		sha_48bit, spa_32bit,
		tha_48bit, tpa_32bit):
		self.htype = htype_16bit
		self.ptype = ptype_16bit
		self.hlen = hlen_8bit
		self.plen = plen_8bit
		self.oper = oper_16bit
		self.sha = sha_48bit
		self.spa = spa_32bit
		self.tha = tha_48bit
		self.tpa = tpa_32bit

	# monta o pacote usando struct, retorna o pacote montado
	def build(self):
		self.size = struct.calcsize("!HHBBH6s4s6s4s")
		return struct.pack("!HHBBH6s4s6s4s",
			self.htype, self.ptype,
			self.hlen, self.plen, self.oper,
			bytes.fromhex(self.sha.replace(':', '')), s.inet_aton(self.spa),
			self.tha, s.inet_aton(self.tpa))

	
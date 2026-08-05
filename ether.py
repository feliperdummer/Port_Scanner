import struct, socket as s

# payload should be None if there is no payload

class Ether:
	def __init__(self,
		dmac_48bit, smac_48bit,
		ethertype_16bit, 
		payload, payload_size):
		self.dmac = dmac_48bit
		self.smac = smac_48bit
		self.ethertype = ethertype_16bit
		self.payload = payload
		self.payload_size = payload_size

	def build(self):
		packet = struct.pack("!6s6sH",
			self.dmac, bytes.fromhex(self.smac.replace(':', '')), 
			self.ethertype)

		# minimum payload size is 46
		if self.payload_size < 46:
			self.payload = self.payload + (b"\x00" * (46 - self.payload_size))
		elif payload > 1500:
			print('ether.py: payload too big (>1500 bytes)')
			return

		packet = packet + self.payload

		return packet


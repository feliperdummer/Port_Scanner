import subprocess

class HostInfo:
	def __init__(self,
		nic_name, 
		inet_addr, inet_subnet
		inet6_addr, mac_addr):

		self.nic_name   = nic_name
		self.inet_addr  = inet_addr
		self.inet6_addr = inet6_addr
		self.mac_addr   = mac_addr




def run_ifconfig():
	out = subprocess.run('ifconfig', capture_output=True, text=True).stdout
	nic_list = re.findall(
		'^[a-zA-Z0-9](?=:)', 
		out, re.MULTILINE)

	inet_list = re.findall(
		'(?<=inet\\s)(?:[0-9]{1,3}.){3}[0-9]{1,3}', 
		out, re.MULTILINE)

	subnet_list = re.findall(
		'(?<=netmask\\s)(?:[0-9]{1,3}.){3}[0-9]{1,3}', 
		out, re.MULTILINE)

	inet6_list = re.findall(
		'(?<=inet6\\s)(?:[a-fA-F0-9]{0,4}:){0,5}[a-fA-F0-9]{0,4}',
		out, re.MULTILINE)

	ether_list = re.findall(
		'(?<=ether\\s)(?:[a-fA-F0-9]{0,2}:){5}[a-fA-F0-9]{0,2}',
		out, re.MULTILINE)
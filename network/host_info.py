import subprocess, re

class NicInfo:
	def __init__(self,
		name, 
		inet, inet_subnet,
		inet6, mac):

		self.name   	 = name
		self.inet   	 = inet
		self.inet_subnet = inet_subnet
		self.inet6       = inet6
		self.mac    	 = mac




def run_ifconfig():
	out = subprocess.run('ifconfig', capture_output=True, text=True).stdout
	nic_list = re.findall(
		'^[a-zA-Z0-9]+:(?=\\s)',  
		out, re.MULTILINE)

	nic_info, i, start = {}, 0, 0
	for i in range(len(nic_list)-1):
		curr = out[start:].split(nic_list[i+1])[0]
		nic_info[nic_list[i][:-1]] = curr
		start = len(curr)
	nic_info[nic_list[-1]] = out[start:]

	nics = []

	for nic, info in nic_info.items():
		inet_addr = re.search(
			'(?<=inet\\s)(?:[0-9]{1,3}.){3}[0-9]{1,3}', info)
		inet_addr = inet_addr.group() if inet_addr else None

		netmask = re.search(
			'(?<=netmask\\s)(?:[0-9]{1,3}.){3}[0-9]{1,3}', info)
		netmask = netmask.group() if netmask else None

		inet6_addr = re.search(
			'(?<=inet6\\s)(?:[a-fA-F0-9]{0,4}:){0,5}[a-fA-F0-9]{0,4}', info)
		inet6_addr = inet6_addr.group() if inet6_addr else None

		ether = re.search(
			'(?<=ether\\s)(?:[a-fA-F0-9]{0,2}:){5}[a-fA-F0-9]{0,2}', info)
		ether = ether.group() if ether else None

		nics.append(NicInfo(nic, inet_addr, netmask, inet6_addr, ether))

	return nics

# define a placa de rede usada pelo host para mandar dados ao destino
# especificado 
def get_nic(T_IP):
	out = subprocess.run(['ip', 'route', 'get', str(T_IP)],
		capture_output=True, text=True).stdout
	nic = re.search('(?<=dev\\s)[0-9a-zA-Z]+(?=\\ssrc)', out)
	return nic.group() if nic else None

for nic in run_ifconfig():
	print(nic.name, nic.inet, nic.inet_subnet, nic.inet6, nic.mac)
	print('\n')
print(get_nic('127.0.0.1'))
print(get_nic('172.20.10.1'))
print(get_nic('1.1.1.1'))
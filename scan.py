import sys, ipaddress, socket, errno, struct, datetime as dt

from scapy.all import sr1, IP, TCP

from network import arp, ether, tcp, ip, icmp, host_info
from extra import flag_parser, errors, extra

def create_ipaddress(T_IP):
	try:
		conn_ip = ipaddress.IPv4Address(T_IP)
	except ValueError:
		conn_ip = None
	return conn_ip

def create_ipnetwork(T_IP):
	try:
		ip_net = ipaddress.IPv4Network(T_IP)
	except ValueError:
		ip_net = None
	return ip_net

def resolve_input_ip(ip_string):
	conn_ip = None
	if '/' in ip_string:
		conn_ip = create_ipnetwork(ip_string)
	if not conn_ip:
		conn_ip = create_ipaddress(ip_string)
	return conn_ip

def exec_arp_ping(T_IP, nic):
	arp_header = arp.Arp(
		1, 
		0x800,
		6,
		4,
		1,
		nic.mac,
		nic.inet,
		'00:00:00:00:00:00',
		str(T_IP)).build()

	ether_header = ether.Ether(
		'FF:FF:FF:FF:FF:FF',
		nic.mac,
		0x806,
		arp_header,
		28).build()

	sock = socket.socket(socket.AF_PACKET, 
		   socket.SOCK_RAW, 
		   socket.htons(0x806))
	sock.settimeout(0.01)
	sock.bind((nic.name, 0))
	sock.send(ether_header)

	try:
		response = sock.recv(1024)
	except TimeoutError:
		response = None
	finally:
		sock.close()

	if response:
		# extrai o header ethernet, equivalente a 14 bytes
		ether_header, remains = ether.Ether.extract(response)

		# caso o pacote payload do ethernet seja do tipo ARP, extrai
		# o header arp do pacote recebido. Equivale a 28 bytes
		if ether_header[2] == 0x0806:
			arp_header, remains = arp.Arp.extract(remains)
		else:
			return 0

		# arp_header[7] e o mac da maquina que espera o arp response, 
		# ou seja, minha maquina
		if bytes.fromhex(nic.mac.replace(':', '')) != arp_header[7]:
			return 0
		
		return 1

	return 0

def exec_syn_ping(T_IP, T_PORT, nic):
	code = 2

	# SYN PACK
	syn_pack = (
		ip.IP(
			6, 
			20, 
			nic.inet, 
			str(T_IP)
		).build()
		+
		tcp.TCPPacket(
			nic.inet,      
			8787,
			str(T_IP),  
			T_PORT,
			0, 		  
			0,
			0b00000010
		).build() 
	)

	sender = socket.socket(
		socket.AF_INET, 
		socket.SOCK_RAW, 
		socket.IPPROTO_RAW
	)
	sender.sendto(syn_pack, (str(T_IP), T_PORT))

	try:
		receiver = socket.socket(
			socket.AF_INET, 
			socket.SOCK_RAW, 
			socket.IPPROTO_TCP
		)
		receiver.settimeout(0.1)
		response, responseSender = receiver.recvfrom(65535)
	except TimeoutError:
		return 2
	finally:
		receiver.close()
		sender.close()

	if responseSender[0] != str(T_IP):
		return 2

	ip_header_extracted, upper_layer_bytes = ip.IP.extract(response)
	
	# extrai os primeiros 20 bytes do upper_layer_bytes pra ter o tcp header
	tcp_header_ext, payload = tcp.TCPPacket.extract(upper_layer_bytes[:20])

	flags = tcp.TCPPacket.extract_flags_only(tcp_header_ext[6])
	if flags[1] and flags[4]: # SYN-ACK -> ABERTA
		return 0
	elif flags[2] and flags[4]: # RST-ACK -> FECHADA
		return 1

	return 2

def exec_icmp_ping(T_IP, nic):
	icmp_data = 1234

	icmp_echo = icmp.Echo(8, icmp_data).build()
	send = socket.socket(
		socket.AF_INET,
		socket.SOCK_RAW,
		socket.IPPROTO_ICMP
	)
	send.sendto(icmp_echo, (str(T_IP), 0))
	try:
		recv = socket.socket(
			socket.AF_INET,
			socket.SOCK_RAW,
			socket.IPPROTO_ICMP
		)
		recv.settimeout(0.1)
		response, sender = recv.recvfrom(65535)
	except TimeoutError:
		return 0
	finally:
		send.close()
		recv.close()

	ip_header, remaining = ip.IP.extract(response)

	if ip_header[10]!=str(T_IP) or ip_header[11]!=nic.inet:
		return 0

	icmp_header = icmp.Echo.extract(remaining)

	if icmp_header[0]!=0 or icmp_header[5]!=icmp_data:
		return 0

	return 1

def try_arp_ping(T_IP, nic):
	return exec_arp_ping(T_IP, nic) == 1

def try_icmp_ping(T_IP, nic):
	return exec_icmp_ping(T_IP, nic) == 1

def try_tcp_ping(T_IP, nic):
	return exec_syn_ping(T_IP, 80, nic) != 2

def host_discovery(T_IP):
	host_nics = host_info.run_ifconfig()

	nic = host_nics.get(host_info.get_nic(T_IP), None)

	if not nic:
		errors.error_exit(-1) 

	if nic.name=='lo':
		return nic

	source_ip = socket.inet_aton(nic.inet)
	netmask   = socket.inet_aton(nic.inet_subnet)
	target_ip = socket.inet_aton(str(T_IP))

	source_ip_network = socket.inet_ntoa(
		(int.from_bytes(source_ip, 'big') &
		 int.from_bytes(netmask,   'big')). \
		 to_bytes(4, 'big'))

	target_ip_network = socket.inet_ntoa(
		(int.from_bytes(target_ip, 'big') &
		 int.from_bytes(netmask,   'big')). \
		 to_bytes(4, 'big'))

	res, count = False, 0
	if source_ip_network == target_ip_network:
		while count < 3 and not res:
			res = try_arp_ping(T_IP, nic)
			count += 1
		if res: return nic

	res, count = False, 0
	while count < 3 and not res:
		res = try_icmp_ping(T_IP, nic)
		count += 1
	if res: return nic

	res, count = False, 0
	while count < 3 and not res:
		res = try_tcp_ping(T_IP, nic)
		count += 1
	if res: return nic

	return None

def exec_self_scan_scapy(T_IP, port, nic):
	response = sr1(
		IP(dst=nic.inet) /
		TCP(dport=port, flags='S'),
		timeout=0.1, verbose=False
	)
	if not response:
		return 2
	if response.haslayer(TCP) and response[TCP].flags=='SA':
		return 0
	elif response[TCP].flags=='R' or response[TCP].flags=='RA':
		return 1

def wide_scan(T_NETWORK, port_list):
	if isinstance(T_NETWORK, ipaddress.IPv6Address):
		errors.error_exit(2)

	print(f'Target Network: {T_NETWORK}\n')

	up, down = [], []

	for host in T_NETWORK.hosts():
		nic = host_discovery(host)
		if not nic: 
			down.append(host)
			continue
		scan_function = exec_self_scan_scapy \
			if nic.name=='lo' else exec_syn_ping
		up.append(host)

		good, bad, unreach = [], [], []

		for port_range in port_list:
			for port in port_range:
				code = scan_function(host, port, nic)
				if code == 0:
					good.append(port)
				elif code == 1:
					bad.append(port)
				else:
					unreach.append(port)

		print('===============================')
		print(f'Target IP: {host}\n')
		print('OPEN: ', good)
		print('CLOSED: ', bad)
		print('NO RESPONSE: ', unreach)
		print('===============================\n')

	print('------------RESULT-------------')
	print(f'HOSTS UP: {len(up)} out of {len(up)+len(down)}')

	return 1

def host_scan(T_IP, port_list):
	if T_IP.version == 6:
		errors.error_exit(2)

	nic = host_discovery(T_IP)

	if not nic:
		print('===============================')
		print(f'{T_IP} INALCANÇÁVEL')
		print('===============================')
		return 1

	unreach, good, bad = [], [], []

	scan_function = exec_self_scan_scapy if nic.name=='lo' \
		else exec_syn_ping

	print('===============================')
	print(f'Target IP: {T_IP}\n')

	for interval in port_list:
		for port in interval:
			code = scan_function(T_IP, port, nic)
			if code == 0:
				good.append(port)
			elif code == 1:
				bad.append(port)
			else:
				unreach.append(port)

	print('OPEN: ', good)
	print('CLOSED: ', bad)
	print('NO RESPONSE: ', unreach)

	print('===============================\n')

	return 0

def main():
	print(f'Scan iniciado em [{dt.datetime.now().strftime("%X %x")}]\n')
	arg_len = len(sys.argv)
	if arg_len != 3:
		errors.error_exit(0)

	ip_string = sys.argv[1]
	port_list_string = sys.argv[2]

	conn_ip = resolve_input_ip(ip_string)
	if not conn_ip:
		errors.error_exit(1)

	try:
		port_list = flag_parser.port_parser(port_list_string)
	except flag_parser.FlagParserException:
		errors.error_exit(4)

	if not port_list:
		errors.error_exit(3)

	if isinstance(conn_ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
		status_code = host_scan(conn_ip, port_list)
	else:
		status_code = wide_scan(conn_ip, port_list)

	print(f'\nScan finalizado em [{dt.datetime.now().strftime("%X %x")}]')

if __name__ == "__main__":
	main()
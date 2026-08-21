import sys, ipaddress, socket, errno, struct
import datetime as dt

from scapy.all import sr1, IP, ICMP, TCP, UDP
from getmac import get_mac_address as getmac

import arp, ether, tcp, ip, flag_parser, errors

local_net_ip_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
local_net_ip_socket.connect_ex(("8.8.8.8", 80))
local_net_ip = local_net_ip_socket.getsockname()[0]
local_net_ip_socket.close()

def create_ipaddress(T_IP):
	try:
		conn_ip = ipaddress.ip_address(T_IP)
	except ValueError:
		conn_ip = None
	return conn_ip

def create_ipnetwork(T_IP):
	try:
		ip_net = ipaddress.ip_network(T_IP)
	except ValueError:
		conn_ip = None
	return ip_net

def resolve_ip_string(ip_string):
	conn_ip = None
	if '/' in ip_string:
		conn_ip = create_ipnetwork(ip_string)
	if not conn_ip:
		conn_ip = create_ipaddress(ip_string)
	return conn_ip

def check_port_range(port_list):
	return (port_list 
			and min(port_list) >= 1
			and max(port_list) <= 65535)

def exec_arp_ping(T_IP):
	global local_net_ip
	arp_header = arp.Arp(
		1, 
		0x800,
		6,
		4,
		1,
		getmac(),
		local_net_ip,
		b'\x00' * 6,
		str(T_IP)).build()

	ether_header = ether.Ether(
		b'\xff' * 6,
		getmac(),
		0x806,
		arp_header,
		28).build()

	sock = 	socket.socket(socket.AF_PACKET, 
			socket.SOCK_RAW, 
			socket.htons(0x806))
	sock.settimeout(0.5)
	sock.bind(("eth0", 0))
	sock.send(ether_header)

	try:
		response = sock.recv(1024)
	except TimeoutError:
		response = None
	finally:
		sock.close()

	if response:
		# extrai o header ethernet, equivalente a 14 bytes
		ether_header = struct.unpack("!6s6sH", response[:14])

		# caso o pacote payload do ethernet seja do tipo ARP, extrai
		# o header arp do pacote recebido. Equivale a 28 bytes
		if ether_header[2] == 0x0806:
			arp_header = struct.unpack("!HHBBH6s4s6s4s", response[14:42])
		else:
			return None

		# arp_header[7] e o mac da maquina que espera o arp response, 
		# ou seja, minha maquina
		if bytes.fromhex(getmac().replace(':', '')) != arp_header[7]:
			return None
		
		return True

	return response

def exec_syn_ping(T_IP, T_PORT):
	code = 2
	global local_net_ip

	# SYN PACK
	syn_pack = (
		ip.IP(
			6, 
			20, 
			local_net_ip, 
			str(T_IP)
		).build()
		+
		tcp.TCPPacket(
			local_net_ip,      
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
		return code
	finally:
		receiver.close()

	if responseSender[0] != str(T_IP):
		return code

	ip_header_extracted, upper_layer_bytes = ip.IP.extract(response)
	
	# extrai os primeiros 20 bytes do upper_layer_bytes pra ter o tcp header
	tcp_header_ext, payload = tcp.TCPPacket.extract(upper_layer_bytes[:20])

	flags = tcp.TCPPacket.extract_flags_only(tcp_header_ext[6])
	if flags[1] and flags[4]: # SYN-ACK -> ABERTA
		code = 0
	elif flags[2]: # RST-ACK -> FECHADA
		code = 1

	sender.close()

	return code

def exec_icmp_ping(T_IP):
	print('icmp executado') # debug
	return sr1(IP(dst=str(T_IP))/
				ICMP(),
					timeout=2, verbose=False)

def exec_tcp_ping(T_IP):
	print('tcp ping executado') # debug
	return exec_syn_ping(T_IP, 80) != 2

def exec_udp_ping(T_IP):
	print('udp ping executado') # debug 
	return sr1(IP(dst=str(T_IP))/ 
				UDP(dport=0),
					timeout=2, verbose=False)

def exec_self_scan_scapy(T_IP, port):
	response = sr1(
		IP(dst='127.0.0.1') /
		TCP(dport=port, flags='S'),
		timeout=1, verbose=False
	)
	if not response:
		return 2
	if response.haslayer(TCP) and response[TCP].flags=='SA':
		return 0
	elif response[TCP].flags=='R' or response[TCP].flags=='RA':
		return 1

def host_discovery(T_IP):
	if T_IP.is_private:
		return exec_arp_ping(T_IP)
	return (exec_icmp_ping(T_IP) or
		    exec_tcp_ping (T_IP) or
		    exec_udp_ping (T_IP)) 

def wide_scan(T_IP, port_list):
	print(f'Target Network: {T_IP}\n')

	for host in T_IP.hosts():
		host_scan(host, port_list)

def host_scan(T_IP, port_list):
	print('===============================')
	print(f'Target IP: {T_IP}\n')

	if T_IP.version == 6:
		errors.error_exit(2)

	scan_function = exec_syn_ping

	# self scan
	if local_net_ip == str(T_IP) or str(T_IP)=='127.0.0.1':
		scan_function = exec_self_scan_scapy
	elif not host_discovery(T_IP):
		print(f'{T_IP} HOST INALCANÇÁVEL')
		print('===============================\n')
		return

	print('PORTA\tESTADO\n')
	for port in port_list:
		code = scan_function(T_IP, port)
		if code == 0:
			print(f'{port}\tABERTA')
		elif code == 1:
			print(f'{port}\tFECHADA')
		elif code == 2:
			print(f'{port}\tSEM RESPOSTA/LIMITE DE TEMPO')
	print('===============================\n')

def main():
	arg_len = len(sys.argv)
	if arg_len != 3:
		errors.error_exit(0)

	ip_string = sys.argv[1]
	port_list_string = sys.argv[2]

	conn_ip = resolve_ip_string(ip_string)
	if not conn_ip:
		errors.error_exit(1)

	try:
		port_list = flag_parser.parse_portas(port_list_string)
	except flag_parser.FlagParsingException:
		errors.error_exit(4)

	if not check_port_range(port_list):
		errors.error_exit(3)

	if isinstance(conn_ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
		status_code = host_scan(conn_ip, port_list)
	else:
		status_code = wide_scan(conn_ip, port_list)

	print(f'Scan finalizado em [{dt.datetime.now().strftime("%X %x")}]')

if __name__ == "__main__":
	main()
import sys, ipaddress as ip, socket
import datetime as dt
import errno
import json
from scapy.all import srp1, sr1, Ether, ARP, IP, ICMP, TCP, UDP

# implementacao mais concreta de host discovery com TCP ping e 
# UDP ping

error_codes = {
	0: 'quantidade de argumentos inválida',
	1: 'endereço de rede inválido',
	2: 'rede não alcançável',
	3: 'ipv6 não suportado por enquanto',
	4: 'número de porta fora limite (1-65535)',
	5: 'formato de porta inválido. Tente "[p1,p2,...,pn]" ou '
		'"[porta]" para uma porta específica'
}

def error_exit(error_code):
	print(f'erro: {error_codes.get(error_code)}')
	print('uso: python port_scan.py [ip_address] "[porta]"')
	sys.exit()

def create_ipaddress(T_IP):
	try:
		conn_ip = ip.ip_address(T_IP)
	except ValueError:
		conn_ip = None
	return conn_ip

def create_ipnetwork(T_IP):
	try:
		ip_net = ip.ip_network(T_IP)
	except ValueError:
		conn_ip = None
	return ip_net

def resolve_ip_string(ip_string):
	conn_ip = None
	if '/' in ip_string:
		conn_ip = create_ipnetwork(ip_string)
	if conn_ip == None:
		conn_ip = create_ipaddress(ip_string)
	return conn_ip

def check_port_range(port_list):
	for port in port_list:
		if port < 1 or port > 65535:
			error_exit(4)

def get_machine_ip():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect_ex(("8.8.8.8", 80))
	ip = s.getsockname()[0]
	sock.close()
	return ip

def exec_arp_ping(T_IP):
	return srp1(Ether(dst="ff:ff:ff:ff:ff:ff")/
				ARP(pdst=str(T_IP)),
					timeout=1, verbose=False)

def exec_icmp_ping(T_IP):
	return sr1(IP(dst=str(T_IP))/
				ICMP(),
					timeout=2, verbose=False)

def exec_tcp_ping(T_IP):
	return sr1(IP(dst=str(T_IP))/
				TCP(dport=80, flags='S'),
					timeout=2, verbose=False)

def exec_udp_ping(T_IP):
	return sr1(IP(dst=str(T_IP))/
				UDP(dport=0),
					timeout=2, verbose=False)

def host_discovery(T_IP, private):
	if private:
		return exec_arp_ping(T_IP)
	return (exec_icmp_ping(T_IP) != None or
		   exec_tcp_ping (T_IP) != None or
		   exec_udp_ping (T_IP) != None) 

def wide_scan(T_IP, port_list):
	print(f'Target Network: {T_IP}\n')

	for host in T_IP.hosts():
		host_scan(host, port_list)

def host_scan(T_IP, port_list):
	print('===============================')
	print(f'Target IP: {T_IP}\n')

	if T_IP.version == 6:
		error_exit(3)

	if host_discovery(T_IP, T_IP.is_private) == None:
		print(f'{T_IP} HOST INALCANÇÁVEL')
		print('===============================\n')
		return

	print('PORTA\tESTADO\n')
	for port in port_list:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(3)
		code = sock.connect_ex((str(T_IP), port))
		if code == 0:
			print(f'{port}\tABERTA')
		elif code == errno.EWOULDBLOCK or code == errno.ETIMEDOUT:
			print(f'{port}\tSEM RESPOSTA/LIMITE DE TEMPO')
		elif code == errno.ECONNREFUSED:
			print(f'{port}\tFECHADA')
		sock.close()
	print('===============================\n')

def main():
	arg_len = len(sys.argv)
	if arg_len != 3:
		error_exit(0)

	ip_string = sys.argv[1]
	port_list_string = sys.argv[2]

	conn_ip = resolve_ip_string(ip_string)
	if conn_ip == None:
		error_exit(1)

	try:
		port_list = json.loads(port_list_string)
	except json.decoder.JSONDecodeError:
		error_exit(5)

	check_port_range(port_list)

	if isinstance(conn_ip, (ip.IPv4Address, ip.IPv6Address)):
		status_code = host_scan(conn_ip, port_list)
	else:
		status_code = wide_scan(conn_ip, port_list)

	print(f'Scan finalizado em [{dt.datetime.now().strftime("%X %x")}]')

if __name__ == "__main__":
	main()
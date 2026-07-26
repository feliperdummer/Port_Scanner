import sys, ipaddress as ip
from scapy.all import IP, TCP, sr1
import datetime

# argumento de linha de comando:
#
# É uma lista chamada argv que pode ser acessada por meio de sys.argv. Por ser
# uma lista, cada elemento pode ser acessado por meio de sys.argv[i];
#
# Como em C, o primeiro argumento (sys.argv[0]) é o nome do scritp sendo rodado
# no momento. A partir de sys.argv[1], são parâmetros passados para execução do
# programa; 

error_codes = {
	0: 'quantidade de argumentos inválida',
	1: 'endereço de rede inválido',
	2: 'rede não alcançável'
}

def error_exit(error_code):
	print(f'erro: {error_codes.get(error_code)}')
	print('uso: python port_scan.py [ip_address]')
	sys.exit()

def create_ipaddress(T_IP):
	try:
		conn_ip = ip.ip_address(T_IP)
	except ValueError:
		return None
	else:
		return conn_ip

def create_ipnetwork(T_IP):
	try:
		ip_net = ip.ip_network(T_IP)
	except ValueError:
		return None
	else:
		return ip_net

def host_scan(T_IP): # arrumar formatacao
	print(f'Target IP: {T_IP}\n')
	p = sr1(IP(dst=str(T_IP))/TCP(dport=(22), flags="S"))
	print(p)
	

def wide_scan(T_IP): # arrumar TUDO
	print(f'Target IP: {T_IP}')
	for host in T_IP.hosts():
		host_scan(host)

def resolve_ip_string(ip_string):
	conn_ip = None
	if '/' in ip_string:
		conn_ip = create_ipnetwork(ip_string)
	if conn_ip == None:
		conn_ip = create_ipaddress(ip_string)
	return conn_ip

def main():
	arg_len = len(sys.argv)
	if arg_len == 1:
		ip_string = '127.0.0.1'
	elif arg_len == 2:
		ip_string = sys.argv[1]
	else :
		error_exit(0)

	conn_ip = resolve_ip_string(ip_string)
	if conn_ip == None:
		error_exit(1)

	if isinstance(conn_ip, (ip.IPv4Address, ip.IPv6Address)):
		status_code = host_scan(conn_ip) # faz um scan de apenas um host
	else:
		status_code = wide_scan(conn_ip) # faz um scan de rede

	if status_code == 2:
		error_exit(2)

	print(f'Scan finalizado em [{datetime.datetime.now().strftime("%X %x")}]')

if __name__ == "__main__":
	main()
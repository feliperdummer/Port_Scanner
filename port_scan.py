import sys, ipaddress as ip, socket
import datetime
import errno
import json



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

def host_scan(T_IP, port_list):
	print(f'Target IP: {T_IP}\n')

	if isinstance(T_IP, ip.IPv6Address):
		error_exit(3)

	print('PORTA\tESTADO\n')
	for port in port_list:
		if port < 1 or port > 65535:
			error_exit(4)
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(3) # duracao da tentativa de conexao
		code = sock.connect_ex((str(T_IP), port))
		if code == 0:
			print(f'{port}\tABERTA')
		elif code == errno.EWOULDBLOCK or code == errno.ETIMEDOUT:
			print(f'{port}\tSEM RESPOSTA/LIMITE DE TEMPO')
		elif code == errno.ECONNREFUSED:
			print(f'{port}\tFECHADA')
		sock.close()
	print('\n\n')
	
def wide_scan(T_IP):
	print(f'Target IP: {T_IP}')

	if isinstance(T_IP, ip.IPv6Address):
		error_exit(3)

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

	if isinstance(conn_ip, (ip.IPv4Address, ip.IPv6Address)):
		status_code = host_scan(conn_ip, port_list)
	else:
		status_code = wide_scan(conn_ip, port_list)

	if status_code == 2:
		error_exit(2)

	print(f'Scan finalizado em [{datetime.datetime.now().strftime("%X %x")}]')

if __name__ == "__main__":
	main()
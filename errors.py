import sys

code_zero = "uso: python port_scan.py (host-ip/network_range) \"[PORTA(S)]\""

code_one = "formato endereco de rede: (0-255).(0-255).(0-255).(0-255)/(0-32)"

code_two = "enderecos do tipo IPv6 ainda nao sao suportados"

code_three = "intervalo de portas possivel: 1 - 65535"

code_four = """
formato de portas incorreto
formatos possiveis:
\t[x,x1,x2,x3,...,xn]
\t[x-xn, y-yn, y, y1, y2, ..., yn]
\t[x]
\t[] ou [-]
(*) todo intervalo deve ter um comeco e um fim
(**) para selecionar todas as portas, utilize '[]' ou '[-]'
(***) para portas notaveis, utilize 'notable'"""

error_codes = {
	0: code_zero,
	1: code_one,
	2: code_two,
	3: code_three,
	4: code_four
}

def error_exit(error_code=0):
	print(f'{error_codes.get(error_code)}')
	if error_code != 0:
		print(f'{error_codes.get(0)}')
	sys.exit()
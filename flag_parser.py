class FlagParsingException(Exception):
	pass

def parse_portas(port_list: str) -> list[int]:
	if len(port_list) < 2:
		raise FlagParsingException('sintaxe de flags incorreta')
	if port_list[0] != '[' or port_list[-1] != ']':
		raise FlagParsingException('sintaxe de flags incorreta')
	if len(port_list) == 2 or len(port_list) == 3:
		if port_list == '[]' or port_list == '[-]':
			return range(1, 65536)
		raise FlagParsingException('sintaxe de flags incorreta')
	port_list = port_list.replace('[', '')

	l = []
	curr_num = 0
	in_interval_init = False # intervalo iniciado
	init_number = 0
	prev_c = None
	for c in port_list:
		if digit(c):
			curr_num = curr_num * 10 + (ord(c) - 48)
		elif c == '-':
			if digit(prev_c):
				init_number = curr_num
				in_interval_init = True
			else:
				raise FlagParsingException('intervalo nao iniciado')
			curr_num = 0
		elif c == ',':
			if digit(prev_c) and in_interval_init:
				if init_number < curr_num:
					step = 1
				else:
					step = -1
				l += range(init_number, curr_num+step, step)
				init_number = 0
				in_interval_init = False
			elif digit(prev_c):
				l.append(curr_num)
			else:
				raise FlagParsingException('sintaxe de flags invalida')
			curr_num = 0
		elif c == ']':
			if digit(prev_c) and in_interval_init:
				if init_number < curr_num:
					step = 1
				else:
					step = -1
				l += range(init_number, curr_num+step, step)
			elif digit(prev_c):
				l.append(curr_num)
			else:
				raise FlagParsingException('sintaxe de flags incorreta')
		prev_c = c
	return sorted(l)

def digit(c):
	return c != None and ord(c) >= 48 and ord(c) <= 57


# formatos validos:
#
#	[x, x1, x2, ..., xn]
#	[x-xn, xn+1, xn+2, ..., xn+m]
# 	[x-xn, xn+1-xn+m, y, y1, ..., yn]
# 	[] ou [-] todas as portas
# 	
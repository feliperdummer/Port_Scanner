import extra

class FlagParserException(Exception): 
	pass

# estados possiveis:
#
#	invalido -> -1
#	inicial  ->  0
#	col_esq  ->  1
#	digito   ->  2
#	hifen	 ->  3
#   virgula  ->  4
#   col_dir  ->  5
#
def new_port_parser(port_list: str) -> list[Range|int]:
	port_range = []
	if port_list == 'notable': 
		return list(extra.notable)
	def transition(state, c):
		match state:
			case 0:
				if c == '[': return 1
				return -1
			case 1:
				if digit(c): return 2
				if c == '-': return 3
				return -1
			case 2:
				if digit(c): return 2
				if c == '-': return 3
				if c == ',': return 4
				if c == ']': return 5
				return -1
			case 3:
				if digit(c): return 2
				if c == ',': return 4
				if c == ']': return 5
				return -1
			case 4:
				if digit(c): return 2
				if c == '-': return 3
				if c == ']': return 5
				return -1
			case _:
				return -1
	open_int, close_int = None, None
	curr_num = 0
	state = 0
	for c in port_list:
		state = transition(state, c)
		if state == -1: 
			raise FlagParserException('err_sintaxe_flag')

def parse_portas(port_list: str) -> list[int]:
	if port_list == 'notable':
		return sorted(list(extra.notable_ports))
	if len(port_list) < 2:
		raise FlagParserException('sintaxe de flags incorreta')
	if port_list[0] != '[' or port_list[-1] != ']':
		raise FlagParserException('sintaxe de flags incorreta')
	if len(port_list) == 2 or len(port_list) == 3:
		if port_list == '[]' or port_list == '[-]':
			return range(1, 65536)
		raise FlagParserException('sintaxe de flags incorreta')
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
				raise FlagParserException('intervalo nao iniciado')
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
				raise FlagParserException('sintaxe de flags invalida')
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
				raise FlagParserException('sintaxe de flags incorreta')
		prev_c = c
	return sorted(l) if min(l) >= 1 and max(l) <= 65535 else None

def digit(c):
	return c and ord(c) >= 48 and ord(c) <= 57


# formatos validos:
#
#	[x, x1, x2, ..., xn]
#	[x-xn, xn+1, xn+2, ..., xn+m]
# 	[x-xn, xn+1-xn+m, y, y1, ..., yn]
# 	[] ou [-] todas as portas
# 	
class FlagParsingException(Exception):
	pass

def parse_portas(port_list: str) -> list[int]:
	port_list = port_list.replace('[', '')
	
	ans = []
	
	curr_num = 0
	in_interval_init = False # intervalo iniciado com numero
	init_number = 0
	in_interval_not_init = False # intervalo comecando em 1
	prev_c = None
	for c in port_list:
		if digit(c):
			curr_num = curr_num * 10 + (ord(c) - 48)
		elif c == '-':
			if prev_c != None and digit(prev_c):
				init_number = curr_num
				in_interval_init = True
			elif prev_c == None or prev_c == ',':
				in_interval_not_init = True
			else:
				raise FlagParsingException('sintaxe de flags incorreta')
			curr_num = 0
		elif c == ',':
			if digit(prev_c) and in_interval_init:
				ans += range(init_number, curr_num+1)
				init_number = 0
				in_interval_init = False
			elif in_interval_init:
				ans += range(init_number, 65536)
				return ans
			elif digit(prev_c) and in_interval_not_init:
				ans += range(1, curr_num+1)
				in_interval_not_init = False
			elif in_interval_not_init:
				ans += range(1, 65536)
				return ans
			elif digit(prev_c):
				ans.append(curr_num)
			curr_num = 0
		elif c == ']':
			if in_interval_init and digit(prev_c):
				ans += range(init_number, curr_num+1)
			elif in_interval_init:
				ans += range(init_number, 65536)
			elif in_interval_not_init and digit(prev_c):
				ans += range(1, curr_num+1)
			elif in_interval_not_init:
				ans += range(1, 65536)
			elif digit(prev_c):
				ans.append(curr_num)
			elif prev_c == ',':
				raise FlagParsingException('sintaxe de flags incorreta')
			break
		prev_c = c
	return ans

def digit(c):
	result = False
	try:
		result = ord(c) >= 48 and ord(c) <= 57
	except TypeError:
		result = False
	return result


# [15-]
# [-]
# [,-]
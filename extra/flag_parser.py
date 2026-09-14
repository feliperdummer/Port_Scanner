from extra import extra

class FlagParserException(Exception): 
	pass

def new_port_parse(port_list: str) -> list[Range]:
	if port_list == 'all':
		all_p = []
		all_p.append(range(1, 65536))
		return all_p
	if port_list == 'notable':
		notable = [sorted(list(extra.notable))]
		return notable

	def transition(state, c):
		match state:
			case 0:
				if c == '[': return 1
				return -1
			case 1:
				if digit(c): return 2
				return -1
			case 2:
				if digit(c): return 2
				if c == ',': return 3
				if c == '-': return 4
				if c == ']': return 6
				return -1
			case 3:
				if digit(c): return 2
				return -1
			case 4:
				if digit(c): return 5
				return -1
			case 5:
				if digit(c): return 5
				if c == ',': return 3
				if c == ']': return 6
				return -1
			case _:
				return -1 

	open_int, curr_num = None,0
	curr_num = 0 
	state = 0

	intervals = []

	for c in port_list:
		if c == ' ': continue
		state = transition(state, c)
		match state:
			case 1:
				pass
			case 2 | 5:
				curr_num = curr_num * 10 + (ord(c)-48)
			case 3 | 6:
				if curr_num <= 0 or curr_num > 65535:
					raise FlagParserException("err_val_inv_flag")
				if open_int:
					if curr_num < open_int:
						open_int, curr_num = curr_num, open_int
				else:
					open_int = curr_num
				intervals.append((open_int, curr_num+1))
				curr_num, open_int = 0, None
			case 4:
				open_int = curr_num
				curr_num = 0
			case _:
				raise FlagParserException('err_sintax_flag')

	# intervals vai ser uma lista de intervalos nesse ponto, 
	# podendo ter intervalos que contem apenas 1 elementos.
	# A ordenacao, por causa da lista ser uma lista de tuplas,
	# compara o primeiro elemento da tupla, ou seja, onde cada
	# intervalo comeca
	intervals.sort()

	# esse trecho de codigo mescla todos os intervalos que
	# podem ser mesclados. Isso ajuda a diminuir o tamanho da 
	# lista de retorno, assim como elimina quaisquer portas
	# que estejam repetidas, seja dentro de um intervalo ou
	# de forma independente.
	#
	# O algoritmo basicamente recebe uma lista de intervalos 
	# ordenados pelo inicio. Compara o intervalo atual com o 
	# ultimo intervalo adicionado. Caso o inicio do intervalo
	# atual seja menor ou igual que o final do ultimo intervalo,
	# eles podem ser mesclados, basta decidir se o intervalo atual
	# termina antes ou depois que o ultimo intervalo. Isso faz com
	# que dois intervalos que se sobrepoe ou que um intervalo que 
	# e interno a outro se tornem um so.
	merged = [range(intervals[0][0], intervals[0][1])]
	for curr_start, curr_end in intervals:
		last_start, last_end = merged[-1][0], merged[-1][-1]+1
		if curr_start <= last_end:
			merged[-1] = range(last_start, max(curr_end, last_end))
		else:
			merged.append(range(curr_start, curr_end))
	return merged

def digit(c):
	return c and ord(c) >= 48 and ord(c) <= 57


# formatos validos:
#
#	[x, x1, x2, ..., xn]
#	[x-xn, xn+1, xn+2, ..., xn+m]
# 	[x-xn, xn+1-xn+m, y, y1, ..., yn]
# 	"all" para todas as portas 
# 	"notable" para portas comuns
Y64 = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._'

def Y64Encode(string_encode: bytes) -> bytes:
	limit = len(string_encode) - (len(string_encode) % 3)
	out = b''
	buff = [0] * len(string_encode)
	i = 0
	hex_start = 0
	hex_end = 2
	
	while i < len(string_encode):
		buff[i] = string_encode[i] & 0xff
		hex_start += 2
		hex_end += 2
		i += 1
	
	i = 0
	
	while i < limit:
		out += bytes([Y64[buff[i] >> 2]])
		out += bytes([Y64[((buff[i] << 4) & 0x30) | (buff[i + 1] >> 4)]])
		out += bytes([Y64[((buff[i + 1] << 2) & 0x3c) | (buff[i + 2] >> 6)]])
		out += bytes([Y64[buff[i + 2] & 0x3f]])
		
		i += 3
	
	i = limit
	
	if (len(string_encode) - i) == 1:
		out += bytes([Y64[buff[i] >> 2]])
		out += bytes([Y64[((buff[i] << 4) & 0x30)]])
		out += b"--"
	elif (len(string_encode) - i) == 2:
		out += bytes([Y64[buff[i] >> 2]])
		out += bytes([Y64[((buff[i] << 4) & 0x30) | (buff[i + 1] >> 4)]])
		out += bytes([Y64[((buff[i + 1] << 2) & 0x3c)]])
		out += b"-"
	
	return out

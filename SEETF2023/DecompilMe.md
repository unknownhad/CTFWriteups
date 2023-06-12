#SEE{s1mP4l_D3c0mp1l3r_XDXD}
from pwn import xor

with open('output.txt', 'rb') as f:
    enc = f.read()

flag_len = len(enc)
a = enc[0:flag_len // 3]
b = enc[flag_len // 3:2 * flag_len // 3]
c = enc[2 * flag_len // 3:]

# reverse the final encryption step
c = xor(c, int(str(flag_len)[0]) * int(str(flag_len)[1]))

# reverse the second round of XOR operations
c = xor(c, b)
b = xor(b, a)
a = xor(a, c)

# reverse the first round of XOR operations
c = xor(c, b)
b = xor(b, a)
a = xor(a, int(str(flag_len)[0]) + int(str(flag_len)[1]))

flag = a + b + c

print(flag.decode())

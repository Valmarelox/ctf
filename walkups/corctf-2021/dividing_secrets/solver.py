#!/usr/bin/env python3.9
from pwn import *
from Crypto.Util.number import long_to_bytes

from tqdm import tqdm
r = remote('crypto.be.ax', 6000)
r.recvuntil(b'g: ')
g = int(r.recvline().strip())
r.recvuntil(b'p: ')
p = int(r.recvline().strip())

r.recvuntil(b'encrypted flag: ')
encrypted_flag = int(r.recvline().strip())

so_far = 0
def get_correct_bits(output):
    for x in range(0, 256):
        if output == pow(g, (so_far << 8)  |x, p):
            return x
    else:
        assert False

for i in tqdm(range(64)):
    to_get =  1 << (512 - ((i + 1) * 8))
    r.recvuntil(b'> ')
    r.sendline(str(to_get).encode())
    value = int(r.recvline().strip())
    chunk = get_correct_bits(value)
    so_far = (so_far << 8) | chunk

print(f'Flag should be {long_to_bytes(so_far)}')

#!/usr/bin/env python3

from pwnlib.tubes.remote import remote
from pwnlib.context import context
from Crypto.Cipher import AES
from Crypto.Util.number import getStrongPrime, isPrime
import string
from tqdm import tqdm
from time import sleep
from codecs import decode
from itertools import count

r = remote("04.cr.yp.toc.tf", 38010)
r.recvuntil(b"uit\n")
r.sendline(b'S')
r.recvuntil(b'enc = ')
flag = int(r.recvline().strip())
print(flag)

def send_test(no, enc):
    assert isinstance(no, int)
    if enc:
        r.sendline(b'E')
    else:
        r.sendline(b'D')
    r.sendline(str(no).encode())
    if enc:
        r.recvuntil(b'encrypt(msg, pubkey) = ')
    else:
        r.recvuntil(b'decrypt(enc, privkey) = ')
    enc = r.readline().strip()
    return int(enc)


def get_key(enc):
    last_y = 0

    key = 0
    nino = 1500
    START = 1 << 1500
    END = 1 << 1560
    for _ in tqdm(range(1600)):
        x = (END+START) // 2
        y = send_test(x, enc)
        key = pow(x,2) - y
        if key != 0:
            END = x
        else:
            START = x
        if END - START <= 1:
            break
    print(f"x = {x}")
    print(f"END={END}")
    print(f"START={START}")
    if key == 0:
        x = END
        y = send_test(x, enc)
        key = pow(x,2) - y

    print(f"Got a key! {key}")
    print(f"Got a key! {key}")
    return key

print(b"Trying to get the pubkey")
with context.local(log_level='debug'):
    N = get_key(True)
import owiener
d = owiener.attack(2, N)
print(f'WOW d={d}')

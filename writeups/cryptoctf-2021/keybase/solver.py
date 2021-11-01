#!/usr/bin/env python3

from pwnlib.tubes.remote import remote
from Crypto.Cipher import AES
import string
from tqdm import tqdm
from time import sleep
from codecs import decode

r = remote("01.cr.yp.toc.tf", 17010)
r.recvuntil(b"uit\n")
r.sendline(b'G')
r.recvuntil(b'encrypt(flag) = ')
flag = r.recvline().strip()
flag = decode(flag, 'hex')
assert len(flag) == 32

def send_test(plain):
    assert len(plain) == 32 and isinstance(plain, bytes)
    r.sendline(b'T')
    r.sendline(plain)
    r.recvuntil(b'enc = ')
    enc = r.readline()
    r.recvuntil(b'key = ')
    key = r.readline()
    return enc, key

while True:
    print("Trying to get enciv and key")
    enciv, key = send_test(b'\x00' * 32)
    if enciv.startswith(b'*'):
        break
    print(f"Got bad {enciv} {key}")
    sleep(1)

enciv, key = enciv.strip(), key.strip()
print(f"Got good {enciv} {key}")
enciv = decode(enciv[-32:], "hex")
assert len(enciv) == 16
key = decode(key.rstrip(b'*'), "hex")
assert len(key) == 14

def decrypttry(aeskey, enc_iv):
    aes = AES.new(aeskey, AES.MODE_ECB)
    dec1 = aes.decrypt(aes.decrypt(enc_iv))
    return dec1

print("Trying to get the iv")
possibleiv = []
for x in tqdm(range(0, 2**16)):
    a,b = x >> 8, x & 0xff
    keytry = key + bytes([a,b])
    possibleiv.append((keytry, decrypttry(keytry, enciv)))

print("Got all key and iv combinations")
    
for key, iv in tqdm(possibleiv):
    aes = AES.new(key, AES.MODE_CBC, iv)
    dec = aes.decrypt(flag)
    if all(chr(x) in string.printable for x in dec):
        print(dec)
        break

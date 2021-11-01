# Keybase
Breaking weird AES-CBC

### Exploit script
[Exploit script](./solver.py)t

### Writeup
The challenge involves decrypting a flag encrypted with aes-cbc with an "almost known key" (we get the key except for the last 2 bytes) but an unknown IV.
We are able to receive the encrypted flag from the server and also get the key (except for the last 2 bytes) and to ask the server to encrypt 32 bytes of data - and in response get back 20 bytes of the encrypted chosen plaintext - the rest have of the nibbles are shown as *.
### Getting the key&iv
To decrypt the encrypted flag - we are missing 2 bytes of the key and the entire iv. attempting all possible keys is easy (there are only 2^16 options).
To get the IV - we need to get creative and abuse the usage of CBC here - a remainder of how cbc encryption works
![](https://upload.wikimedia.org/wikipedia/commons/thumb/8/80/CBC_encryption.svg/600px-CBC_encryption.svg.png)

How do we abuse this to get the iv? we use the fact the plaintext is xored with the IV before the AES encryption takes place, send 32 bytes of '\0' to the server - which will cause something very nice to happen - We will basically get the IV encrypted twice using normal AES-ECB as the second block of the encryption - which is important, because in the responses the server only returns a part of the first block - but sometimes the entire second block (so lets request an encrytion multiple times until we have an entire second block.
So for each key guess - we try to decrypt the `twice_encrypted_iv` and get an iv guess - again there are only 2^16 options - so bruteforcing is trivial.
For each key&IV pair - try to decrypt the flag, and break on the first plaintext that contains only printable characters.
After running the script we get `CTF{h0W_R3cOVER_7He_5eCrET_1V?}'`
### Script
```python
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

```

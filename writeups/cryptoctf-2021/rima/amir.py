#!/usr/bin/env python3
from Crypto.Util.number import bytes_to_long, isPrime
from gmpy2 import digits
from tqdm import tqdm
from sympy.ntheory import factorint
from codecs import decode
with open('g.enc', 'rb') as f:
    g= bytes_to_long(f.read())
with open('h.enc', 'rb') as f:
    h = bytes_to_long(f.read())


g = [int(x) for x in digits(g, 5)]
h = [int(x) for x in digits(h, 5)]

def find_c(data):
    a = {}
    for c in tqdm(range(1, len(data))):
        if not isPrime(c):
            continue
        test = data[:]
        for i in range(len(test) - c - 1, -1, -1):
            test[i] -= test[i+c]
        if not any(test[:c]):
            a[c] = test
        # I am lazy
        if len(a) == 2:
            break
    return a

all_options_g = find_c(g)
all_options_h = find_c(h)
l = set(all_options_g).intersection(set(all_options_h))
assert len(l) == 1
l = list(l)
#print(l)
c = l[0]
assert c == 67
g = all_options_g[c][c:]
h = all_options_h[c][c:]
#print(all_options_g, all_options_h)
def do_array(arr):
    factors = list(factorint(len(arr)).keys())
    del factors[0]
    print(factors[1])
    x = [arr[i:i+factors[1]] for i in range(0, len(arr), factors[1])]
    print(factors)
    print(arr[:100])
    print(x.count(x[0]),len(x))

def nextPrime(n):
    while True:
         n += (n % 2) + 1
         if isPrime(n):
             return n
# len(f) must b 1 mod 8
#print(factorint(len(h)))
#factors = list(factorint(len(h)).keys())
#print(factors)
#factors = list(factorint(len(g)).keys())
a = 257
b = 263
f1 = g[:len(g) // a]
f2 = h[:len(h) // b]
assert f1 == f2

for x in range(len(f2) - 2, -1, -1):
    f2[x] -= f2[x+1]
del f2[0]
#print(f2)
print(decode(hex(int(''.join(str(x) for x in f2), 2))[2:], 'hex'))
#do_arrayb(g)

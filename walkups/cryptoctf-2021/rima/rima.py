#!/usr/bin/env python

from Crypto.Util.number import *
from flag import FLAG

def nextPrime(n):
    while True:
        n += (n % 2) + 1
        if isPrime(n):
            return n

# bits
f = [int(x) for x in bin(int(FLAG.hex(), 16))[2:]]

# F[0:n-1] +=  F[1:n]
f.insert(0, 0)
for i in range(len(f)-1): 
    f[i] += f[i+1]

# First prime after len(f)
a = nextPrime(len(f))
b = nextPrime(a)

# f * a
#g = [x for i in range(a) for x in f]
g = f * a
# h = [y for i in range(b) for y in f]
h = f * b

c = nextPrime(len(f) >> 2)

for _ in [g, h]:
    # add c amount of prefix zeroes
    for __ in range(c): 
        _.insert(0, 0)
    for i in range(len(_) -  c): 
        _[i] += _[i+c]

g, h = [int(''.join([str(x) for x in nino]), 5) for nino in [g, h]]

for _ in [g, h]:
    if _ == g:
        fname = 'g'
    else:
        fname = 'h'
    of = open(f'{fname}.enc', 'wb')
    of.write(long_to_bytes(_))
    of.close()

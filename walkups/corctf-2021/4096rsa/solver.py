#!/usr/bin/env python3
from sympy.ntheory import factorint
from Crypto.Util.number import isPrime, long_to_bytes
from functools import reduce

n, c, _ = open('output.txt', 'rt').read().split('\n')
n = int(n)
c = int(c)
e = 65537

def br(n):
     known_prime_factors = []
     print(f'Factoring {n}... ',end="",flush=True)
     factors = factorint(n, use_trial=False,use_rho=False, use_pm1=False, use_ecm=True)
     if len(factors) == 1:
         factors = factorint(n)
     pfactors = sum(([x]*y for x,y in factors.items()), [])
     rem_factors = [x for x in pfactors if not isPrime(x)]
     known_prime_factors = [x for x in pfactors if isPrime(x)]
     print("done")
     for p in rem_factors:
         known_prime_factors += br(p)
     return known_prime_factors

factors = br(n)
phi_n = reduce(lambda x,y: x * (y-1), factors, 1)
d = pow(e, -1, phi_n)
flag = long_to_bytes(pow(c, d, n))
print(f'Flag is {flag}')

#!/usr/bin/env python3
fib = [1, 1]
for i in range(2, 11):
    fib.append(fib[i - 1] + fib[i - 2])


def c2f(c):
    n = ord(c)
    b = ''
    for i in range(10, -1, -1):
        if n >= fib[i]:
            n -= fib[i]
            b += '1'
        else:
            b += '0'
    return b

def f2c(f):
    n = 0
    for bit, c in zip(f, fib[::-1]):
        if bit == '1':
            n += c
    return chr(n)


enc= open('flag.enc', 'r').read()
flag = ''
for c in enc.split(' '):
    flag += f2c(c)
print(flag)

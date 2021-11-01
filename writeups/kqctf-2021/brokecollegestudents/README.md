# KQCTF 2021 brokecollegestudents challenge
Override global variable with format string attack on a PIE executable
### Writeup
A relativly simple exploit - `MONEY` is a global variable and we have a format string vulnurability in the binary, so lets exploit it to set the most signifcant byte of `MONEY`
running `checksec` on the binary:
```bash
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
We have PIE enabled - so we need to find the address of `MONEY` using a leak, lets use the same format string vulnurability to leak an absolute address.
In my exploit - I chose to leak the return address from the call to `catch` as it is easily locatable in the stack - so a simple `%n$lx` would suffice.
Exploiting the vulnurability twice allows us to buy the flag :)
Full Exploit: [code](./college.py)

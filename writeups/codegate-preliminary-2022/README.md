# ARVM  
I started reversing the challenge after I saw that simple shellcodes get
blacklisted - then I saw that the assembly is very convoluted so I moved to
testing stuff empirically.

The main bypass to the assembly whitelist in the challenge is the use of the
cool fact that ARM supports (at least for some instructions) conditional
variants of those instructions. the challenge checks explicitly for the
existence of the `SVC` opcode (0xe8XXXXXX), catches some conditional variants of
it, but doesn't blacklist `SVCGE` - so we use that to do syscalls by setting
CCR properly before hand (the sub that always results in a positive result)

The second hack is that we need to bypass the fact that we cannot access the PC
and SP registers (at least not in a straight forward way I found empirically) -
and to use execve we need a memory address that contains "/bin/sh" - also, STR &
LDR opcodes are forbidden. So to bypass these two facts - I allocate memory
using the mmap syscall (to have some valid writable memory) and then write
"/bin/sh" to it using the read syscall that reads from stdin (to bypass the STR
opcode blacklist)
Enjoy :)

Rough shellcode:
```c
    void* ptr = mmap(0, PAGESIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
    MAP_PRIVATE|MAP_ANON, 0, -1);
    read(0, ptr, sizeof("/bin/sh"))
    execve(ptr, NULL, NULL);
```


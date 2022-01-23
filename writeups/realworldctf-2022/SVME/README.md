### SVME Solution
A pretty cool pwn challenge - which has lots of elements you need to work with -
the binary is pretty well compiled (stack canaries, PIE and the like), so
exploitation isn't trivial. also exploiting in a random assembly language is
always fun.
#### Walkup
So first things first I started looking at the attached binary and saw
horrendous disassembly in the `vm_exec` function - (due to the implementation of
the main interpreter switch case as a jump table which my IDA didn't parse
well). then continuing by looking at the sources that are pointed to by the
dockerfile - a nice open source project on [github](https://github.com/parrt/simple-virtual-machine-C).
looking at the sources - I started looking for exploit primitives and found two
interesting ones revolving around the fact that there is no validation on the 
value of sp - and it starts by pointing into the `vm_struct` structure - so we 
can easily cause the stack pointer to point to any element of the struct - 
using pop/load/store/iconst...
The primitives that we have from that:
1. Absolute memory read&write - overriding the value of `globals` allows us to read/write
   to arbitrary memory locations using gload/gstore.
2. Stack location leak: looking at the creation of the struct - we see that the
   `code` field points to a stack local variable of the `main` function - we can
   leak that address using the `load` opcode.
3. Return address override: using the previous primitive we can calculate the return
   address's address on the stack - therefore we can also override it using
   our first primitive.
4. Binary&libc location: using the stack location leak - we can also leak the
   libc and binary locations to break PIE&ASLR. I chose to do this by
   calculating `read_ptr` and then derefing it to get `read` in libc. in
   hindsight I could have chosen a different value from the stack in order to
   get an address in libc (the return address of main's call stack)

With this primitives we do the following:
1. Leak the return address to a local variable
2. Calculate `read_ptr` from last step
3. Calculate location of `pop rdi; ret`&`ret` ROP gadgets
4. Calculate `read` from last step
5. Calculate `system` from the last step
6. Execute a ROP Chain by overriding the return address location:
    1. jump to `ret` gadget to align the stack
    2. jump to `pop rdi; ret` gadget
    3. location in stack of the 'sh' string
    4. jump to `system`
    5. 'sh' string
7. profit - get interactive shell and `cat /flag`

### Full solution
[solve.py](./solve.py)

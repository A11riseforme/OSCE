import sys
import math
from pwn import *

string = sys.argv[1]

stack_slot_size = 4

shellcode = b""

if not len(string)%stack_slot_size:
    print("xor ebx, ebx")
    shellcode += asm("xor ebx, ebx")
    print("push ebx")
    shellcode += asm("push ebx")

string += "\x00"*(math.ceil(len(string)/stack_slot_size)*stack_slot_size-len(string))

string = string[::-1]

for i in range(int(len(string)/stack_slot_size)):
    tmp = string[i*stack_slot_size:i*stack_slot_size+stack_slot_size]
    print("push 0x"+''.join(str(hex(ord(j)))[2:].zfill(2) for j in tmp))
    shellcode += asm("push 0x"+''.join(str(hex(ord(j)))[2:].zfill(2) for j in tmp))

print(''.join("\\x%02x" % i for i in shellcode))

import sys
import math
from pwn import *

ip = sys.argv[1]

ips = ip.split('.')[::-1]

print("push 0x"+"".join(str(hex(int(i)))[2:].zfill(2) for i in ips))

print(''.join("\\x%02x" % i for i in asm("push 0x"+"".join(str(hex(int(i)))[2:].zfill(2) for i in ips))))

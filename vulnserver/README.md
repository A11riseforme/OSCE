All the exploits I created for the [vulnserver](https://github.com/stephenbradshaw/vulnserver)

All the scripts were developed under Windows 7 Enterprise, 6.1.7601 Service Pack 1 Build 7601, 64-bit, and are provided as is.

#### GMON/poc.py

standard seh overwrite with egghunter technique

#### GTER/poc.py

can be exploited using egghunter technique as well. I chose to call `LoadLibrary` to load the malicious dll through unc path. The shellcode was written in a very crude manner, in order to fit inside the buffer.

#### HTER/poc.py

weird way of filling buffer. need to be careful with stack alignment.

#### KSTET/poc.py

can be exploited using egghunter technique as well. I chose to re-use the socket to retrieve the second stage shellcode. While receiving the second stage payload, another bof occurs. Exploit the eip overwrite to jmp to esp and execute the shellcode

#### LTER/poc.py

when buffer length is short(around 3500), eip get overwritten. only characters in [0x01,0x79] are allowed. Use msfvenom to generate a PURELY alphanumeric shellcode by specifying the BufferRegister to be esp.

when buffer length is long(around 4000), seh get overwritten. Much more complicated than the case above. Need to write the shellcode with limited character set and perform three jmp to reach the beginning of the buffer. Then perform the sub encoding technique to push the actual shellcode onto the stack, finally handover to the actual shellcode and execute.

#### TRUN/poc.py

standard eip overwrite
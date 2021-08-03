
_CLIENT_BUFFER = 040H

virtual at _USER_CODE_VIRTUAL
_client::
    rept 0500H { nop }
    xor eax, eax
    mov al, _SYSCALL_ARGCPY
    int 030H
    mov ebp, dword [_USER_SHELL_ARGUMENT_VIRTUAL]
    xor eax, eax
    mov al, _SYSCALL_SPGRP
    int 030H
    test eax, eax
    js _client_exit
    mov al, _SYSCALL_GPID
    int 030H
    push eax
    xor eax, eax
    mov al, _SYSCALL_IOCTL
    mov ebx, _TELETYPE_CURRENT
    mov ecx, TIOCSPGRP
    mov edx, esp
    int 030H
    lea edi, [esp+4H-_CLIENT_BUFFER]
_client_loop:
    xor eax, eax
    mov al, _SYSCALL_ALIVE
    mov ebx, ebp
    xor ecx, ecx
    mov cl, _SERVER_PORT
    int 030H
    test eax, eax
    js _client_exit
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _client_prompt
    mov edx, _client_prompt.sizeof
    int 030H
    xor eax, eax
    mov al, _SYSCALL_READ
    mov ebx, _TELETYPE_CURRENT
    mov ecx, edi
    xor edx, edx
    mov dl, _CLIENT_BUFFER
    int 030H
    test eax, eax
    jz _client_loop
    mov esi, eax
    cmp byte [edi+eax-1H], 00AH
    jnz $+3H
    dec esi
    mov edx, edi
    xor eax, eax
    mov al, _SYSCALL_SEND
    mov ebx, ebp
    xor ecx, ecx
    mov cl, _SERVER_PORT
    int 030H
    jmp _client_loop
_client_exit:
    xor eax, eax
    mov al, _SYSCALL_EXIT
    xor ebx, ebx
    int 030H

_client_send string "HELLO"
_client_prompt string "$> "
_client_sending string "You are about to send the string "
_client.sizeof = ($ - $$)
end virtual

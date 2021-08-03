
virtual at _USER_CODE_VIRTUAL
_init::
    xor eax, eax
    mov al, _SYSCALL_SHA1
    int 030H

    ;xor eax, eax
    ;mov al, _SYSCALL_AESENC_ECB
    ;lea ebx, [esp-010H]
    ;mov dword [ebx], "HELO"
    ;mov ebx, _aes_test
    ;mov ecx, 010H
    ;mov edx, _aes_key
    ;int 030H

    jmp $

_aes_test:
    db 032H, 088H, 031H, 0E0H
    db 043H, 05AH, 031H, 037H
    db 0F6H, 030H, 098H, 007H
    db 0A8H, 08DH, 0A2H, 034H

_aes_key:
    db 02BH, 028H, 0ABH, 009H
    db 07EH, 0AEH, 0F7H, 0CFH
    db 015H, 0D2H, 015H, 04FH
    db 016H, 0A6H, 088H, 03CH

    xor eax, eax
    mov al, _SYSCALL_FORK
    int 030H
    test eax, eax
    jnz _init_parent
    xor ecx, ecx
    mov cl, _TELETYPE_COUNT
_init_parent_teletype:
    mov eax, _SYSCALL_FORK
    int 030H
    test eax, eax
    jnz _init_parent_loop
    lea esi, [ecx-_TELETYPE_COUNT]
    neg esi
    mov eax, _SYSCALL_SSID
    int 030H
    mov dword [esp-4H], eax
    mov eax, _SYSCALL_IOCTL
    mov ebx, esi
    mov ecx, TIOCSCTTY
    xor edx, edx
    int 030H
    xor eax, eax
    mov al, _SYSCALL_IOCTL
    mov ebx, esi
    mov ecx, TIOCSPGRP
    lea edx, [esp-4H]
    int 030H
    mov eax, _SYSCALL_EXEC
    mov ebx, _login_payload
    mov ecx, _login.sizeof
    int 030H
_init_parent_loop:
    loop _init_parent_teletype
    xor eax, eax
    mov al, _SYSCALL_EXIT
    xor ebx, ebx
    int 030H
_init_parent:
    xor eax, eax
    mov al, _SYSCALL_WAITPID
    mov ebx, _WAIT_ALL
    xor ecx, ecx
    xor edx, edx
    mov dl, (WEXITED or WNOHANG)
    int 030H
    jmp _init_parent
_extract _login
_init.sizeof = ($ - $$)
end virtual


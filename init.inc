
virtual at _USER_CODE_VIRTUAL
_init::
    mov eax, _SYSCALL_FORK
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



virtual at _USER_CODE_VIRTUAL
_bomb::
_bomb_start:
    xor eax, eax
    mov al, _SYSCALL_FORK
    int 030H
    test eax, eax
    jns _bomb_start
    xor eax, eax
    mov al, _SYSCALL_EXIT
    xor ebx, ebx
    int 030H
_bomb.sizeof = ($ - $$)
end virtual

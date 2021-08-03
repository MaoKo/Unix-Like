
virtual at _USER_CODE_VIRTUAL
_sqrt::
    xor eax, eax
    mov al, _SYSCALL_ARGCPY
    int 030H
    xor eax, eax
    mov al, _SYSCALL_EXIT
    xor ebx, ebx
    int 030H
_sqrt.sizeof = ($ - $$)
end virtual

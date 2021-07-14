
virtual at _USER_CODE_VIRTUAL
_hostname::
    xor eax, eax
    mov al, _SYSCALL_ARGCPY
    int 030H
    cmp dword [_USER_SHELL_ARGUMENT_VIRTUAL], 0H
    jz _hostname_start
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _hostname_invalid
    mov edx, _hostname_invalid.sizeof
    int 030H
    mov ebx, (not 0H)
    jmp _hostname_start_exit
_hostname_start:
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _hostname_value
    mov edx, _hostname_value.sizeof
    int 030H
    xor ebx, ebx
_hostname_start_exit:
    xor eax, eax
    mov al, _SYSCALL_EXIT
    int 030H
_hostname_value string "CP/M2 Workstation", 00AH
_hostname_invalid string "hostname invalid usage", 00AH
_hostname.sizeof = ($ - $$)
end virtual

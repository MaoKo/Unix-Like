
_user_code _print
    xor eax, eax
    mov al, _SYSCALL_ARGCPY
    int 030H
    mov ebp, dword [_USER_SHELL_ARGUMENT_VIRTUAL]
    test ebp, ebp
    jnz _print_string
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _print_invalid
    mov edx, _print_invalid.sizeof
    int 030H
    jmp _print_exit 
_print_string:
    mov ecx, (_USER_SHELL_ARGUMENT_VIRTUAL + 4H)
    mov edx, ebp
_print_loop:
    xor eax, eax
    mov al, _SYSCALL_WRITE
    int 030H
    test eax, eax
    jns _print_loop
_print_exit:
    xor eax, eax 
    mov al, _SYSCALL_EXIT
    int 030H
_print_invalid string "print need an arguments", 00AH
end _user_code

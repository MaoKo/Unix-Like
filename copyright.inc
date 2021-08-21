
_user_code _copyright
    xor eax, eax
    mov al, _SYSCALL_ARGCPY
    int 030H
    cmp dword [_USER_SHELL_ARGUMENT_VIRTUAL], 0H
    jz _copyright_start
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _copyright_invalid
    mov edx, _copyright_invalid.sizeof
    int 030H
    mov ebx, (not 0H)
    jmp _copyright_exit
_copyright_start:
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _copyright_display
    mov edx, _copyright_display.sizeof
    int 030H
    xor ebx, ebx
_copyright_exit:
    xor eax, eax
    mov al, _SYSCALL_EXIT
    int 030H
_copyright_display string\
    "Copyright achiu-au@42", 00AH,\
    "License MIT, this kernel is for educational purpose only", 00AH
_copyright_invalid string "copyright invalid usage", 00AH
end _user_code

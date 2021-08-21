
_user_code _uname
    xor eax, eax
    mov al, _SYSCALL_ARGCPY
    int 030H
    cmp dword [_USER_SHELL_ARGUMENT_VIRTUAL], 0H
    jz _uname_start
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _uname_invalid
    mov edx, _uname_invalid.sizeof
    int 030H
    mov ebx, (not 0H)
    jmp _uname_exit
_uname_start:
    xor eax, eax
    mov al, _SYSCALL_UNAME
    lea ebx, [esp-_UNAME_SIZE]
    int 030H
    mov edx, eax
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ecx, ebx
    mov ebx, _TELETYPE_CURRENT
    int 030H
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ecx, _uname_newline
    mov edx, _uname_newline.sizeof
    int 030H
    xor ebx, ebx
_uname_exit:
    xor eax, eax
    mov al, _SYSCALL_EXIT
    int 030H   
_uname_invalid string "uname invalid usage"
_uname_newline string 00AH
end _user_code

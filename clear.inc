
virtual at _USER_CODE_VIRTUAL
_clear::
    rept 0E00H {nop} 
    xor eax, eax
    mov al, _SYSCALL_ARGCPY
    int 030H
    cmp dword [_USER_SHELL_ARGUMENT_VIRTUAL], 0H
    jz _clear_start
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _clear_invalid
    mov edx, _clear_invalid.sizeof
    mov ebx, (not 0H)
    jmp _clear_exit
_clear_start:
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _clear_clear
    mov edx, _clear_clear.sizeof
    int 030H
    ; XXX Termios
    xor ebx, ebx
_clear_exit:
    xor eax, eax
    mov al, _SYSCALL_EXIT
    int 030H
_clear_invalid string "clear invalid usage", 00AH
_clear_clear string _ESCAPE, _ESCAPE_CLEAR
_clear.sizeof = ($ - $$)
end virtual

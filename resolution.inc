
virtual at _USER_CODE_VIRTUAL
_resolution::
    xor eax, eax
    mov al, _SYSCALL_ARGCPY
    int 030H
    mov ecx, dword [_USER_SHELL_ARGUMENT_VIRTUAL]
    test ecx, ecx
    jnz _resolution_start
_resolution_error:
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _resolution_invalid
    mov edx, _resolution_invalid.sizeof
    int 030H
    mov ebx, (not 0H)
    jmp _resolution_exit
_resolution_start:
    mov esi, (_USER_SHELL_ARGUMENT_VIRTUAL + 4H)
    call _vdso_atoi
    jc _resolution_error
    jecxz _resolution_error
    mov ebp, eax
    mov al, 020H
    mov edi, esi
    rep scasb
    lea esi, [edi-1H]
    inc ecx
    call _vdso_atoi
    jc _resolution_error
    mov edi, esi
    mov esi, eax
    jecxz _resolution_change
    mov al, 020H
    rep scasb
    jnz _resolution_error
_resolution_change:
    xor eax, eax
    mov al, _SYSCALL_IOCTL
    mov ebx, _TELETYPE_CURRENT
    xor ecx, ecx
    mov cl, TIOCSWINSZ
    lea edx, [esp-_winsize.sizeof]
    mov word [edx+_winsize.ws_xpixel], bp
    mov word [edx+_winsize.ws_ypixel], si
    int 030H
    test eax, eax
    jns _resolution_exit-2H
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _resolution_permission
    mov edx, _resolution_permission.sizeof
    int 030H
    xor ebx, ebx
_resolution_exit:
    xor eax, eax
    mov al, _SYSCALL_EXIT
    int 030H
_resolution_permission string "resolution permission denied", 00AH
_resolution_invalid string "resolution invalid usage", 00AH
_resolution.sizeof = ($ - $$)
end virtual

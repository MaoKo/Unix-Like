
virtual at _USER_CODE_VIRTUAL
_kill::
    xor eax, eax
    mov al, _SYSCALL_ARGCPY
    int 030H
    mov ecx, dword [_USER_SHELL_ARGUMENT_VIRTUAL]
    test ecx, ecx
    jnz _kill_start
_kill_error:
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _kill_invalid
    mov edx, _kill_invalid.sizeof
    int 030H
    mov ebx, (not 0H)
    jmp _kill_exit
_kill_start:
    mov esi, (_USER_SHELL_ARGUMENT_VIRTUAL + 4H)
    call _vdso_atoi
    jc _kill_error
    jecxz _kill_error
    mov ebp, eax
    mov al, 020H
    mov edi, esi
    rep scasb
    lea esi, [edi-1H]
    inc ecx
    call _vdso_atoi
    jc _kill_error
    mov edi, esi
    mov esi, eax
    jecxz _kill_send
    mov al, 020H
    rep scasb
    jnz _kill_error
_kill_send:
    xor eax, eax
    mov al, _SYSCALL_KILL
    mov ebx, esi
    mov ecx, ebp
    int 030H
    xor ebx, ebx
_kill_exit:
    xor eax, eax
    mov al, _SYSCALL_EXIT
    int 030H
_kill_invalid string "kill invalid usage", 00AH
_kill.sizeof = ($ - $$)
end virtual


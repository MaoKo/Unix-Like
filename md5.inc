
virtual at _USER_CODE_VIRTUAL
_md5::
    xor eax, eax
    mov al, _SYSCALL_ARGCPY
    int 030H
    mov ebp, dword [_USER_SHELL_ARGUMENT_VIRTUAL]
    test ebp, ebp
    jnz _md5_hash
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _md5_invalid
    mov edx, (_md5_invalid.sizeof + 1H)
    int 030H
    mov ebx, (not 0H)
    jmp _md5_exit
_md5_hash:
    ;mov esi, (_USER_SHELL_ARGUMENT_VIRTUAL + 4H)

    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _md5_head
    mov edx, _md5_head.sizeof
    int 030H
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ecx, (_USER_SHELL_ARGUMENT_VIRTUAL + 4H)
    mov edx, ebp
    int 030H
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ecx, _md5_tail
    mov edx, _md5_tail.sizeof
    int 030H
    xor eax, eax
    mov al, _SYSCALL_MD5

    ;mov ebx, (_USER_SHELL_ARGUMENT_VIRTUAL + 4H)
    ;mov ecx, ebp

    ;mov ebx, _abcx
    ;mov ecx, 0

    lea edx, [esp-_MD5_DIGEST]
    int 030H
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    lea ecx, [esp-_MD5_DIGEST]
    mov edx, _MD5_DIGEST
    int 030H
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _md5_newline
    xor edx, edx
    inc dl
    int 030H
    xor ebx, ebx
_md5_exit:
    xor eax, eax
    mov al, _SYSCALL_EXIT
    int 030H

;_md5_example string "The quick brown fox jumps over the lazy dog"

;_abcx string ""

_md5_head string "md5("""
_md5_tail string """) = "
_md5_invalid string "md5 invalid usage"
_md5_newline: db 00AH
_md5.sizeof = ($ - $$)
end virtual



virtual at _USER_CODE_VIRTUAL
_uid::
    xor eax, eax
    mov al, _SYSCALL_ARGCPY
    int 030H
    cmp dword [_USER_SHELL_ARGUMENT_VIRTUAL], 0H
    jz _uid_start
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _uid_invalid
    mov edx, _uid_invalid.sizeof
    int 030H
    mov ebx, (not 0H)
    jmp _uid_exit
_uid_start:
    xor eax, eax
    mov al, _SYSCALL_GUID
    int 030H
    cmp eax, _ROOT_UID
    mov ebx, _uid_root
    mov ecx, _uid_root.sizeof
    jz _uid_display
    call _uid_itoa
_uid_display:
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov edx, ecx
    mov ecx, ebx
    mov ebx, _TELETYPE_CURRENT
    int 030H
    xor ebx, ebx
_uid_exit:
    xor eax, eax
    mov al, _SYSCALL_EXIT
    int 030H
_uid_itoa:
 ; in: eax - target number
 ; out:
 ;  ebx - pointer to the string
 ;  ecx - count
    pop esi
    std
    mov ebx, eax
    lea edi, [esp-1H]
    mov al, 00AH
    stosb
    xor ecx, ecx
    inc cl
    mov eax, ebx
    xor edx, edx
    xor ebp, ebp
    mov ebp, 00AH
_uid_itoa_loop:
    div ebp
    xchg edx, eax
    add al, 030H
    stosb
    xor eax, eax
    xchg edx, eax
    inc ecx
    test eax, eax
    jnz _uid_itoa_loop
    lea ebx, [edi+1H]
    jmp esi
_uid_invalid string "uid invalide usage", 00AH
_uid_root string "root", 00AH
_uid.sizeof = ($ - $$)
end virtual


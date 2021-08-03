
virtual at _USER_VDSO_VIRTUAL
_vdso::
_vdso_sigret:
    xor eax, eax
    mov al, _SYSCALL_SIGRET
    int 030H
_vdso_sysenter:
    pop ebp edx ecx
    int 030H
    ret

_vdso_itoa:
 ; in: eax - target number
 ; out:
 ;  ebx - pointer to the string
 ;  ecx - count
    pop esi
    std
    lea edi, [esp-1H]
    xor ecx, ecx
    xor edx, edx
    mov ebp, 00AH
_vdso_itoa_loop:
    div ebp
    xchg edx, eax
    add al, 030H
    stosb
    xor eax, eax
    xchg edx, eax
    inc ecx
    test eax, eax
    jnz _vdso_itoa_loop
    lea ebx, [edi+1H]
    cld
    jmp esi

_vdso_atoi:
 ; in:
 ;  esi - source string
 ;  ecx - size of string
 ; out:
 ;  eax - number
 ;  esi - updated
 ;  ecx - updated
 ;   cf - if not a number or overflow
    xor eax, eax
    cdq
    jecxz _vdso_atoi_exit
    lodsb
    call _vdso_is_digit
    jc _vdso_atoi_revert+1H
    jmp _vdso_atoi_mulitiply
_vdso_atoi_loop:
    lodsb
    call _vdso_is_digit
    jc _vdso_atoi_revert
_vdso_atoi_mulitiply:
    imul edx, edx, 00AH
    add edx, eax
    jc _vdso_atoi_exit
    loop _vdso_atoi_loop
    jmp _vdso_atoi_exit
_vdso_atoi_revert:
    clc
    dec esi
_vdso_atoi_exit:
    mov eax, edx
    ret

_vdso_is_digit:
    sub al, 030H
    jc _vdso_is_digit_exit
    cmp al, 00AH
    cmc
_vdso_is_digit_exit:
    ret

_vdso.sizeof = ($ - $$)
end virtual

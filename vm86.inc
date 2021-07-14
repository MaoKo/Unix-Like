
_GENERAL_FAULT = 00DH
_vm86_monitor:
 ; in: [esp+4H] - last retframe
 ; out: cf - set if the fault was not caused by a sensitive instruction (cli/sti/pushf/popf/iret/int) or for hlt
    lea esi, [esp+4H]
    movzx eax, word [esi+_x86_register.eip]
    movzx ebx, word [esi+_x86_register.cs]
    _real_segment edx, ebx:eax
    mov ebp, ebx
    mov ebx, edx
    movzx eax, word [esi+_x86_register.esp]
    movzx edi, word [esi+_x86_register.ss]
    _real_segment edi, edi:eax
    xor edx, edx
    cmp dword [esi+_x86_register.trap], _GENERAL_FAULT
    jnz _vm86_monitor_examine
    xor ecx, ecx
    mov cl, 010H
_vm86_monitor_loop:
    call _vm86_monitor_prefix
    jnc _vm86_monitor_examine
    cmp byte [ebx], _OPERAND_SIZE
    jnz _vm86_monitor_update
    mov dl, (not 0H)
_vm86_monitor_update:
    inc ebx
    loop _vm86_monitor_loop
_vm86_monitor_examine:
    push _vm86_monitor_ip
    cmp dword [esi+_x86_register.trap], _GENERAL_FAULT
    jnz _vm86_monitor_int
    cmp byte [ebx], _PUSHF
    jz _vm86_monitor_pushf
    cmp byte [ebx], _POPF
    jz _vm86_monitor_popf
    cmp byte [ebx], _INT
    jz _vm86_monitor_int
    cmp byte [ebx], _IRET
    jz _vm86_monitor_iret
    cmp byte [ebx], _STI
    jz _vm86_monitor_sti
    cmp byte [ebx], _CLI
    jz _vm86_monitor_cli
    cmp byte [ebx], _HLT
    jz _vm86_monitor_hlt
    pop eax
    stc
    jmp _vm86_monitor_exit
_vm86_monitor_ip:
    sub ebx, ebp
    mov dword [esi+_x86_register.eip], ebx
    clc
_vm86_monitor_exit:
    ret
_vm86_monitor_prefix:
 irp _prefix*, _REP,_REPNZ,_CS,_DS,_ES,_SS,_FS,_GS,_LOCK,_OPERAND_SIZE,_ADDRESS_SIZE
 {
    cmp byte [ebx], _prefix
    jz _convert_zero_carry
 }
    clc
    ret

_vm86_monitor_pushf:
    inc ebx
    mov eax, dword [esi+_x86_register.eflags]
    test eax, _EFLAGS_VIF
    jz _vm86_monitor_pushf_size
    or eax, _EFLAGS_IF
_vm86_monitor_pushf_size:
    and eax, (not (_EFLAGS_VM or _EFLAGS_RF))
    or eax, (011B shl _EFLAGS_IOPL)
    test dl, dl
    jz _vm86_monitor_pushf_word
    and eax, (not (_EFLAGS_VIF or _EFLAGS_VIP)) ; hide the fact that the real mode program run in a vm ;)
    sub word [esi+_x86_register.esp], 4H
    mov dword [edi-4H], eax
    ret
_vm86_monitor_pushf_word:
    sub word [esi+_x86_register.esp], 2H
    mov word [edi-2H], ax
    ret
    
_vm86_monitor_popf:
    inc ebx
    mov ecx, dword [esi+_x86_register.eflags]
    and ecx, (_EFLAGS_VIP or _EFLAGS_IF)
    test dl, dl
    jz _vm86_monitor_popf_word
    mov eax, dword [edi]
    add word [esi+_x86_register.esp], 4H
    jmp _vm86_monitor_popf_next
_vm86_monitor_popf_word:
    movzx eax, word [edi]
    add word [esi+_x86_register.esp], 2H
_vm86_monitor_popf_next:
    and eax, (not (011B shl _EFLAGS_IOPL))
    or eax, _EFLAGS_VM
    test eax, _EFLAGS_IF
    jz _vm86_monitor_popf_if
    or eax, _EFLAGS_VIF
_vm86_monitor_popf_if:
    or eax, ecx
    mov dword [esi+_x86_register.eflags], eax
    ret

_vm86_monitor_iret:
    xor ebp, ebp
    test dl, dl
    jz _vm86_monitor_iret_word
    mov eax, dword [edi]
    mov bp, 4H
    jmp _vm86_monitor_iret_next
_vm86_monitor_iret_word:
    movzx eax, word [edi]
    mov bp, 2H
_vm86_monitor_iret_next:
    mov cx, word [edi+ebp]
    mov dword [esi+_x86_register.eip], eax
    mov word [esi+_x86_register.cs], cx
    shl ebp, 1H
    add word [esi+_x86_register.esp], bp
    add edi, ebp
    call _vm86_monitor_popf
    mov dword [esp], _vm86_monitor_exit-1H
    ret

_vm86_monitor_int:
    xor dl, dl
    call _vm86_monitor_pushf
    mov dx, word [esi+_x86_register.cs]
    mov word [edi-4H], dx
    lea edx, [ebx+1H]
    movzx eax, byte [ebx]
    cmp dword [esi+_x86_register.trap], _GENERAL_FAULT
    jz _vm86_monitor_int_compute
    mov eax, dword [esi+_x86_register.trap]
    sub edx, 2H
    sub ebx, 2H
_vm86_monitor_int_compute:
    sub edx, ebp
    mov word [edi-6H], dx
    movzx edx, word [eax*4H]
    mov cx, word [eax*4H+2H]
    mov word [esi+_x86_register.eip], dx
    mov word [esi+_x86_register.cs], cx
    sub word [esi+_x86_register.esp], 4H
    mov dword [esp], _vm86_monitor_exit-1H
_vm86_monitor_cli:
    inc ebx
    mov eax, dword [esi+_x86_register.eflags]
    test byte [_singleton.vme], 1H
    jnz _vm86_monitor_cli_vme
    mov edx, dword [_current]
    xor al, al
    mov byte [edx+_process.vif], al
    ret
_vm86_monitor_cli_vme:
    and eax, (not _EFLAGS_VIF)
    mov dword [esi+_x86_register.eflags], eax
    ret

_vm86_monitor_sti:
    inc ebx
    mov eax, dword [esi+_x86_register.eflags]
    test byte [_singleton.vme], 1H
    jnz _vm86_monitor_sti_vme
    mov edx, dword [_current]
    mov al, 1H
    mov byte [edx+_process.vif], al
    ret
_vm86_monitor_sti_vme:
    or eax, _EFLAGS_VIF
    mov dword [esi+_x86_register.eflags], eax
    ret

_vm86_monitor_hlt:
    jmp _execute_real_terminate

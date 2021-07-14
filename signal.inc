
_send_signal_current:
    mov ebx, dword [_current]
_send_signal:
 ; in:
 ;  eax - target signal
 ;  ebx - process object pointer
 ; out: cf - bad signal or no enough privilege to send the signal
 ; preserves: ebx, esi, edi, ebp
 ; note: SIGCONT is send even if uid are different but are in the same session
    push ebx edi
    mov edx, eax
    inc dword [ebx+_process.sigcnt]
    test edx, edx
    jz _send_signal_carry
    cmp edx, _SIGNALS
    jae _send_signal_carry
    call _uid_enough_permission
    jo _send_signal_cont
    jnc _send_signal_carry
    cmp edx, SIGCONT
    jnz _send_signal_queue
    jmp _send_signal_wake
_send_signal_cont:
    cmp edx, SIGCONT
    jnz _send_signal_carry
_send_signal_wake:
    call _default_action_cont
_send_signal_queue:
    ; XXX handle SIGKILL and SIGSTOP
    lea ebx, [ebx+_process.pending]
    mov eax, edx
    xchg eax, ebx
    call _send_signal_set
    jmp _send_signal_carry+1H
_send_signal_carry:
    stc
    pop edi ebx
    ret
_send_signal_set:
 ; in: 
 ;   eax - pending signal bitmap object pointer
 ;   ebx - signal
 ; preserves: eax, esi, ebp
    call _convert_signal_bitmask
    xor ecx, ecx
    inc cl
    mov edi, _BITMAP_SET
    call _bitmap_update
    ret

_send_signal_process_group_current:
    mov ebx, dword [_current]
    mov ebx, dword [ebx+_process.grpdesc]
_send_signal_process_group:
 ; in:
 ;  eax - target signal
 ;  ebx - _process_group_descriptor object pointer
 ; preserves: ebx, esi, edi, ebp
    push ebx esi ebp 
    test eax, eax
    jz _send_signal_process_group_exit
    cmp eax, _SIGNALS
    jae _send_signal_process_group_exit
    mov ebp, eax
    lea eax, [ebx+_process_group_descriptor.prclist]
    mov ecx, _process.pgroup
    xor edx, edx
    mov dl, (_LIST_FORWARD or _LIST_SAVE_ALL)
    mov esi, _send_signal_process_group_iterate
    call _find_list
_send_signal_process_group_exit:
    cmc
    pop ebp esi ebx
    ret
_send_signal_process_group_iterate:
    mov eax, ebp
    jmp _send_signal

_handle_signal:
 ; out: cf - set if the handler is inaccesible for the user
 ; preserves: esi, edi, ebp
    push esi edi ebp
    push 0H ; _signal_context pointer pointer
    mov ebp, dword [_current]
    lea eax, dword [ebp+_process.pending]
    xor ebx, ebx
    mov edx, ebx
    lea ecx, [ebx+1H]
    call _bitmap_search
    jc _handle_signal_exit
    push edx
    mov edi, _BITMAP_RESET
    call _bitmap_update
    pop edx
    sub ebx, dword [eax+_bitmap.next]
    lea eax, dword [ebp+_process.sigmask]
    add ebx, dword [eax+_bitmap.next]
    mov edi, _BITMAP_SET
    call _bitmap_match
    jc _handle_signal_exit
    call _convert_bitmask_signal
    mov edi, ebx
    cmp edi, SIGKILL
    jz _handle_signal_default
    cmp edi, SIGSTOP
    jz _handle_signal_default
    shl ebx, (bsf _signal_context.sizeof)
    lea ebx, [ebp+_process.signals+ebx]
    mov dword [esp], ebx
    cmp byte [ebx+_signal_context.assign], 0H
    jz _handle_signal_default
    mov ebx, dword [ebx+_signal_context.handler]
    mov esi, ebx
    call _memory_accessible
    jnc _handle_signal_user
_handle_signal_default:
    mov esi, dword [_signal_default_table+edi*4H]
    mov eax, edi
    mov ebx, ebp
    call esi
    jmp _handle_signal_exit
_handle_signal_user:
    mov eax, dword [esp]
    cmp byte [eax+_signal_context.nested], 0H
    jz _handle_signal_sigframe
    lea eax, dword [ebp+_process.pending]
    mov ebx, edi
    call _send_signal_set
    jmp _handle_signal_exit+1H
_handle_signal_sigframe:
    cmp byte [eax+_signal_context.newfrm], 0H
    jnz _handle_signal_copy
    push edi
    xor eax, eax
    mov al, _ALLOCATION_VIRTUAL
    mov edi, _frame_cache 
    call _allocate_from_cache
    pop edi
    jc _handle_signal_exit+1H
    mov eax, dword [esp]
    mov dword [eax+_signal_context.sigframe], ebx
    mov byte [eax+_signal_context.newfrm], (not 0H)
_handle_signal_copy:
    inc byte [ebp+_process.signst]
    mov bl, byte [ebp+_process.signst]
    mov byte [eax+_signal_context.nested], bl
    push esi edi
    mov esi, dword [ebp+_process.retframe]
    mov edi, dword [eax+_signal_context.sigframe]
    mov ecx, _x86_register.sizeof
    call _copy_string
    pop edi esi
    mov ebp, dword [ebp+_process.retframe]
    mov ebx, dword [ebp+_x86_register.esp]
    sub ebx, 4H
    call _memory_accessible_userspace
    jc _handle_signal_exit+1H
    mov dword [ebx], _vdso_sigret
    mov dword [ebp+_x86_register.esp], ebx
    mov dword [ebp+_x86_register.eip], esi
    mov dword [ebp+_x86_register.eax], edi
_handle_signal_exit:
    clc
    lea esp, [esp+4H]
    pop ebp edi esi
    ret
_signal_default_table:
    dd 0H ; signal begin with 1H
    dd _default_action_term
    dd _default_action_term
    dd _default_action_core
    dd _default_action_core
    dd _default_action_core
    dd _default_action_core
    dd _default_action_core
    dd _default_action_core
    dd _default_action_core
    dd _default_action_term
    dd _default_action_term
    dd _default_action_core
    dd _default_action_term
    dd _default_action_term
    dd _default_action_term
    dd _default_action_term
    dd _default_action_term
    dd _default_action_ign
    dd _default_action_cont
    dd _default_action_stop
    dd _default_action_stop
    dd _default_action_stop
    dd _default_action_stop
_signal_default_table_end:

_default_action_term: 
 ; in: 
 ;  eax - signal number
 ;  ebx - current process
    mov byte [ebx+_process.extsig], al
    jmp _syscall_exit

_segmentation_fault string "Segmentation fault", 00AH
_illegal_instruction string "Illegal instruction", 00AH
_abort string "Aborted", 00AH
_bus_fault string "Bus error", 00AH
_segmentation_core:
    mov eax, SIGSEGV
_default_action_core:
 ; in: 
 ;  eax - signal number
 ;  ebx - current process
    mov byte [ebx+_process.extsig], al
    cmp dword [ebx+_process.pid], _INIT_PID
    ja _default_action_switch
    mov byte [ebx+_process.panic], (not 0H)
_default_action_switch:
    mov ebx, _TELETYPE_CURRENT
    cmp eax, SIGSEGV
    mov ecx, _segmentation_fault
    mov edx, _segmentation_fault.sizeof
    jz _default_action_core_display
    cmp eax, SIGILL
    mov ecx, _illegal_instruction
    mov edx, _illegal_instruction.sizeof
    jz _default_action_core_display
    cmp eax, SIGABRT
    mov ecx, _abort
    mov edx, _abort.sizeof
    jz _default_action_core_display
    cmp eax, SIGBUS
    mov ecx, _bus_fault
    mov edx, _bus_fault.sizeof
    jnz _default_action_core_exit
_default_action_core_display:
    call _syscall_write
_default_action_core_exit:
    jmp _syscall_exit

_default_action_ign:
 ; in:
 ;  eax - signal number
 ;  ebx - current process
    ret

_wakeup_parent:
 ; in: ebx - child process object pointer
 ; preserves: ebx, edx, esi, edi, ebp
    push ebx edx
    cmp ebx, dword [_initproc]
    jz _wakeup_parent_exit
    mov eax, dword [ebx+_process.parent]
    mov eax, dword [eax+_process.channel] ; don't wakeup if the parent is in the STOP state
    call _wakeup_channel
_wakeup_parent_exit:
    pop edx ebx
    ret

_default_action_cont:
 ; in:
 ;  eax - signal number
 ;  ebx - current process
 ; preserves: ebx, edx, esi, edi, ebp
    cmp dword [ebx+_process.state], _PROCESS_STOP
    jnz _default_action_cont_exit
    mov dword [ebx+_process.state], _PROCESS_RUN
    mov byte [ebx+_process.waitable], _PROCESS_WAITABLE
    mov eax, dword [ebx+_process.grpdesc]
    dec dword [eax+_process_group_descriptor.stopped]
    call _wakeup_parent
_default_action_cont_exit:
    ret

_default_action_stop:
 ; in:
 ;  eax - signal number
 ;  ebx - current process
    cmp dword [ebx+_process.state], _PROCESS_STOP
    jz _default_action_stop_sleep
    mov dword [ebx+_process.state], _PROCESS_STOP
    mov byte [ebx+_process.waitable], _PROCESS_WAITABLE
    mov byte [ebx+_process.sigstp], al
    mov eax, dword [ebx+_process.grpdesc]
    inc dword [eax+_process_group_descriptor.stopped]
    call _wakeup_parent
_default_action_stop_sleep:
    call _sleep_channel
    jmp _switch_mapping_user
    ; XXX sure to need switch user mapping ??

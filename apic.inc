
enum _EDGE_TRIGGER, _LEVEL_TRIGGER
enum _LOW_POLARITY, _HIGH_POLARITY
struct _interrupt_mapping _irq*, _gsi*, _trigger*, _polarity*, _vector*
    assert      ((_strinit) | ((_vector) >= 8H))
    .irq:       db (_irq) ; old PC-AT IRQ
    .gsi:       dd (_gsi)
    .trigger:   db (_trigger)
    .polarity:  db (_polarity)
    .vector:    db (_vector)
ends

_DEFAULT_ISA_TRIGGER    = _EDGE_TRIGGER
_DEFAULT_ISA_POLARITY   = (not (_LOW_POLARITY or _HIGH_POLARITY))
_interrupt_mapping_table:
    _pit            _interrupt_mapping 0H, 0H, _DEFAULT_ISA_TRIGGER, _DEFAULT_ISA_POLARITY, _pit_irq.vector
    _keyboard       _interrupt_mapping 1H, 1H, _DEFAULT_ISA_TRIGGER, _DEFAULT_ISA_POLARITY, _keyboard_irq.vector
    _com2           _interrupt_mapping 3H, 3H, _DEFAULT_ISA_TRIGGER, _DEFAULT_ISA_POLARITY, _com2_irq.vector
    _com1           _interrupt_mapping 4H, 4H, _DEFAULT_ISA_TRIGGER, _DEFAULT_ISA_POLARITY, _com1_irq.vector
    _lpt2           _interrupt_mapping 5H, 5H, _DEFAULT_ISA_TRIGGER, _DEFAULT_ISA_POLARITY, _lpt2_irq.vector
    _floppy         _interrupt_mapping 6H, 6H, _DEFAULT_ISA_TRIGGER, _DEFAULT_ISA_POLARITY, _floppy_irq.vector
    _lpt1           _interrupt_mapping 7H, 7H, _DEFAULT_ISA_TRIGGER, _DEFAULT_ISA_POLARITY, _lpt1_irq.vector
    _rtc            _interrupt_mapping 8H, 8H, _DEFAULT_ISA_TRIGGER, _DEFAULT_ISA_POLARITY, _rtc_irq.vector
    _vga_retrace    _interrupt_mapping 9H, 9H, _DEFAULT_ISA_TRIGGER, _DEFAULT_ISA_POLARITY, _vga_retrace_irq.vector
    _mouse          _interrupt_mapping 00CH, 00CH, _DEFAULT_ISA_TRIGGER, _DEFAULT_ISA_POLARITY, _mouse_irq.vector
    _fpu            _interrupt_mapping 00DH, 00DH, _DEFAULT_ISA_TRIGGER, _DEFAULT_ISA_POLARITY, _fpu_irq.vector
    _hdd            _interrupt_mapping 00EH, 00EH, _DEFAULT_ISA_TRIGGER, _DEFAULT_ISA_POLARITY, _hdd_irq.vector
_interrupt_mapping_table_end:

_soft_enable_apic:
    or dword [_PAE_LOCAL_APIC+_SPURIOUS_INTERRUPT_VECTOR_REGISTER], _SPURIOUS_APIC_ENABLE
    ret

_soft_disable_apic:
    and dword [_PAE_LOCAL_APIC+_SPURIOUS_INTERRUPT_VECTOR_REGISTER], (not _SPURIOUS_APIC_ENABLE)
    ret

_hard_disable_apic:
    ret

_acpi_find_sdt_table:
 ; in: 
 ;  ebx - RSDT table
 ;  edx - SDT signature
 ; out:
 ;  ebx - target SDT table
 ;   cf - set if table not found
 ; preserves: esi, edi, ebp
    push esi edi
    cmp dword [ebx+_acpi_sdt_header.signature], _RSDT
    jnz _acpi_find_sdt_table_exit
    mov edi, ebx
    call _acpi_sdt_checksum
    jc _acpi_find_sdt_table_exit+1H
    mov ecx, dword [ebx+_acpi_sdt_header.length]
    sub ecx, _acpi_sdt_header.sizeof
    shr ecx, 2H
    jecxz _acpi_find_sdt_table_exit
    lea esi, [ebx+_acpi_sdt_header.sizeof]
_acpi_find_sdt_table_loop:
    lodsd
    cmp dword [eax+_acpi_sdt_header.signature], edx
    jnz _acpi_find_sdt_table_update
    mov edi, eax
    mov ebx, ecx
    call _acpi_sdt_checksum 
    xchg edi, ebx
    jnc _acpi_find_sdt_table_exit+1H
    mov ecx, edi
_acpi_find_sdt_table_update:
    loop _acpi_find_sdt_table_loop
_acpi_find_sdt_table_exit:
    stc
    pop edi esi
    ret

enum _LOCAL_APIC_ACCESS_READ, _LOCAL_APIC_ACCESS_WRITE
_local_apic_access_register:
 ; in:
 ;  ebx     - access kind
 ;  ecx     - kind of register to write
 ;  edx:eax - data to be written (edx is written iff x2APIC is enabled and ICR register is trageted)
 ; out:
 ;  eax = read register (if ebx = _LOCAL_APIC_ACCESS_READ else unmodified)
 ;  ecx = value such that this function can be called twice to access to the same register
 ;   cf - set if error
 ; preserves: ebx, esi, edi, ebp
    cmp ebx, (_LOCAL_APIC_ACCESS_WRITE + 1H)
    cmc
    jc _local_apic_access_register_exit
    test byte [_singleton.apic], 1H
    stc
    jz _local_apic_access_register_exit
    test byte [_singleton.x2apic], 1H
    jnz _local_apic_access_register_x2apic
    cmp ecx, _SELF_IPI_MSR
    jz _local_apic_access_register_exit
    cmp bl, _LOCAL_APIC_ACCESS_READ
    jz _local_apic_access_register_read
    mov dword [_LOCAL_APIC+ecx], eax
    jmp _local_apic_access_register_exit
_local_apic_access_register_read:
    mov eax, dword [_LOCAL_APIC+ecx]
    jmp _local_apic_access_register_exit
_local_apic_access_register_x2apic:
    mov word [_local_apic_access_register_execute], _RDMSR
    cmp bl, _LOCAL_APIC_ACCESS_WRITE
    jnz _local_apic_access_register_sanitize
    mov word [_local_apic_access_register_execute], _WRMSR
_local_apic_access_register_sanitize:
    cmp ecx, _DESTINATION_FORMAT_REGISTER
    jz _local_apic_access_register_exit ; silently ignored
    cmp ecx, _SELF_IPI_MSR
    jz _local_apic_access_register_write
    cmp ecx, _INTERRUPT_COMMAND_REGISTER_HIGH
    jnz _local_apic_access_register_shift
    mov ecx, _INTERRUPT_COMMAND_REGISTER_MSR
    jmp _local_apic_access_register_write+2H
_local_apic_access_register_shift:
    shr ecx, _X2APIC_MSR_SHIFT
_local_apic_access_register_write:
    xor edx, edx
    add ecx, _LOCAL_APIC_BASE_MSR
_local_apic_access_register_execute:
    dw 0H
    sub ecx, _LOCAL_APIC_BASE_MSR
    cmp ecx, _SELF_IPI_MSR
    jz _local_apic_access_register_exit
    shl ecx, _X2APIC_MSR_SHIFT
_local_apic_access_register_exit:
    ret

_io_apic_irq_count:
 ; out:
 ;  eax - number of IRQ attached to the target IO APIC
 ;   cf - set if there are no io apic in the system
 ; note: [_PAE_IO_APIC] - point to valid io apic registers set
 ; preserves: ebx, ecx, edx, esi, edi, ebp
    cmp byte [_io_apic_count], 0H
    stc
    jz _io_apic_irq_count_exit
    mov byte [_PAE_IO_APIC+_INDEX_REGISTER], _IO_APIC_VERSION_REGISTER
    mov eax, dword [_PAE_IO_APIC+_DATA_REGISTER]
    and eax, _IO_APIC_VERSION_IRQ_RT_MASK
    shr eax, _IO_APIC_VERSION_IRQ_RT_SHIFT
    inc eax
_io_apic_irq_count_exit:
    ret

_io_apic_reset_rt:
 ; out: cf - set if there are no io apic in the system
 ; preserves: ecx
    push ecx
    call _io_apic_irq_count
    jc _io_apic_reset_rt_exit
    xor ecx, ecx
_io_apic_reset_rt_loop:
    cmp ecx, eax
    jae _io_apic_reset_rt_exit
    lea edx, [_REDIRECTION_TABLE_BASE+ecx*2H]
_io_apic_reset_rt_reset:
    mov byte [_PAE_IO_APIC+_INDEX_REGISTER], dl
    mov dword [_PAE_IO_APIC+_DATA_REGISTER], _APIC_MASK
    inc dl
    cmp dl, 2H
    jb _io_apic_reset_rt_reset
    inc ecx
    jmp _io_apic_reset_rt_loop
_io_apic_reset_rt_exit:
    pop ecx
    ret

_io_apic_irq_connect:
 ; in:
 ;  ebx - madt table (point to the current io apic entry)
 ;  ecx - remain madt size
 ; out: cf - set if there are no io apic in the system
 ; preserves: ebx, ecx, ebp
    push ebx ecx ebp
    call _io_apic_irq_count
    jc _io_apic_irq_connect_exit
    mov ebp, dword [ebx+_madt_io_apic.gsi_base]
    add eax, ebp
_io_apic_irq_connect_loop:
    mov dl, byte [ebx+_madt_prefix.type]
    cmp dl, _MADT_INTERRUPT_OVERRIDE  
    jz _io_apic_irq_connect_interrupt
    cmp dl, _MADT_NMI
    jnz _io_apic_irq_connect_update
    jmp _io_apic_irq_connect_mapping
_io_apic_irq_connect_interrupt:
    mov dl, byte [ebx+_madt_interrupt_override.irq]
    mov edi, _interrupt_mapping_table
_io_apic_irq_connect_mapping:
    cmp dl, byte [edi+_interrupt_mapping.irq]
    jnz _io_apic_irq_connect_advance
    movzx edx, word [ebx+_madt_interrupt_override.flags]
    mov esi, edx
    and edx, _INTERRUPT_EL_MASK
    shr edx, _INTERRUPT_EL_SHIFT
    cmp dl, _INTERRUPT_EL_LEVEL
    mov edx, esi
    jnz _io_apic_irq_connect_copy
    mov byte [edi+_interrupt_mapping.trigger], _LEVEL_TRIGGER
    mov byte [edi+_interrupt_mapping.polarity], _LOW_POLARITY
    and edx, _INTERRUPT_PO_MASK
    shr edx, _INTERRUPT_PO_SHIFT 
    cmp dl, _INTERRUPT_PO_HIGH
    jnz _io_apic_irq_connect_copy
    mov byte [edi+_interrupt_mapping.polarity], _HIGH_POLARITY
_io_apic_irq_connect_copy: 
    lea esi, [ebx+_madt_interrupt_override.gsi]
    add edi, _interrupt_mapping.gsi
    movsd
    jmp _io_apic_irq_connect_update 
_io_apic_irq_connect_advance:
    cmp edi, _interrupt_mapping_table_end
    jae _io_apic_irq_connect_update
    add edi, _interrupt_mapping.sizeof
    jmp _io_apic_irq_connect_mapping
_io_apic_irq_connect_update:
    movzx edx, byte [ebx+_madt_prefix.length]
    add ebx, edx
    sub ecx, edx
    jnz _io_apic_irq_connect_loop
    mov edi, _interrupt_mapping_table
_io_apic_irq_connect_redirection:
    mov edx, dword [edi+_interrupt_mapping.gsi]
    cmp edx, eax
    jae _io_apic_irq_connect_iterate
    sub edx, ebp
    jc _io_apic_irq_connect_iterate
    lea edx, [_REDIRECTION_TABLE_BASE+edx*2H+1H]
    mov byte [_IO_APIC+_INDEX_REGISTER], dl
    mov dword [_IO_APIC+_DATA_REGISTER], (_XAPIC_MESSAGE_BROADCAST shl (_XAPIC_DESTINATION_SHIFT - 020H))
    dec dl
    mov byte [_IO_APIC+_INDEX_REGISTER], dl
    mov dl, byte [edi+_interrupt_mapping.vector]
    or edx, _APIC_DELIVERY_FIXED
    cmp byte [edi+_interrupt_mapping.trigger], _EDGE_TRIGGER
    jz _io_apic_irq_connect_activate
    or edx, _APIC_LEVEL_TRIGGER
    cmp byte [edi+_interrupt_mapping.polarity], _HIGH_POLARITY
    jz _io_apic_irq_connect_activate
    or edx, _APIC_POLARITY_LOW
_io_apic_irq_connect_activate:
    mov dword [_IO_APIC+_DATA_REGISTER], edx
_io_apic_irq_connect_iterate:
    cmp edi, _interrupt_mapping_table_end
    jae _io_apic_irq_connect_exit
    add edi, _interrupt_mapping.sizeof
    jmp _io_apic_irq_connect_redirection
_io_apic_irq_connect_exit:
    pop ebp ecx ebx
    ret

;_acpi_parse_madt:
;    ret


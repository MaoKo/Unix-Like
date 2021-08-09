
_KERNEL_START = 0200000H
assert (~(_KERNEL_START and _PAGE_OFFSET_MASK))

format ELF executable 3H at _KERNEL_START
entry _kernel_start
use32

include "system.inc"

_GRUB1_MAGIC        = 01BADB002H
_GRUB2_MAGIC        = 0E85250D6H
_GRUB1_FLAGS        = 0H
_GRUB1_MULTIBOOT    = 02BADB002H
_GRUB2_MULTIBOOT    = 036D76289H
_GRUB2_ARCHITECTURE = 0H
macro __grub_multiboot _version*
{
    local _current, _checksum
    assert (((_version) = 1H) | ((_version) = 2H))
    segment executable writable readable
    align 8H
    _grub_header_start:
    dd _GRUB#_version#_MAGIC
    _checksum = _GRUB#_version#_MAGIC
    if ((_version) = 1H)
        dd _GRUB1_FLAGS
        _checksum = ((_checksum) + _GRUB#_version#_FLAGS)
    else
        dd _GRUB2_ARCHITECTURE
        dd (_grub_header_end - _grub_header_start)
        _checksum = ((_checksum) + _GRUB2_ARCHITECTURE + (_grub_header_end - _grub_header_start))
    end if
    dd (-(_checksum))
    if ((_version) = 2H)
        dw 0H
        dw 0H
        dd 8H
    end if
    _grub_header_end:
}

_MULTIBOOT_MEM = (1H shl 0H)
_MULTIBOOT_DEV = (1H shl 1H)
_MULTIBOOT_CMD = (1H shl 2H)
struct _multiboot_info _flags*, _mem_lower*, _mem_upper*, _boot_devices*, _cmdline*, _mods_count*, _mods_addr*
    .flags:         dd 0H
    .mem_lower:     dd (_mem_lower)
    .mem_upper:     dd (_mem_upper)
    .boot_devices:  dd (_boot_devices)
    .cmdline:       dd (_cmdline)
    .mods_count:    dd (_mods_count)
    .mods_addr:     dd (_mods_addr)
ends

__grub_multiboot 1

_VESA_SIGNATURE = "VESA"
_VBE2_SIGNATURE = "VBE2"
struct _vbe_info_block _signature*, _version*, _oem_string*, _capabilities*, _video_mode*, _total_memory*, _oem_software*, _oem_vendor*, _oem_product*, _oem_revision*
    .signature:     dd (_signature)
    .version:       dw (_version)
    .oem_string:    dd (_oem_string)
    .capabilities:  dd (_capabilities)
    .video_mode:    dd (_video_mode)
    .total_memory:  dw (_total_memory)
    .oem_software:  dw (_oem_revision)
    .oem_vendor:    dd (_oem_vendor)
    .oem_product:   dd (_oem_product)
    .oem_revision:  dd (_oem_revision)
    .reserved:      db 0DEH dup 0H
    .oem_data:      db 100H dup 0H
ends

_VBE_ATTRIBUTE_SUPPORT      = (1H shl 0H)
_VBE_ATTRIBUTE_RESERVED     = (1H shl 1H)
_VBE_ATTRIBUTE_TTY_OUTPUT   = (1H shl 2H)
_VBE_ATTRIBUTE_COLOR        = (1H shl 3H)
_VBE_ATTRIBUTE_GRAPHICS     = (1H shl 4H)
_VBE_ATTRIBUTE_LINEAR       = (1H shl 7H)

_VBE_MEMORY_MODEL_TEXT      = 0H
_VBE_MEMORY_MODEL_CGA       = 1H
_VBE_MEMORY_MODEL_HERCULES  = 2H
_VBE_MEMORY_MODEL_PLANAR    = 3H
_VBE_MEMORY_MODEL_PACKED    = 4H
_VBE_MEMORY_MODEL_NON_CHAIN = 5H
_VBE_MEMORY_MODEL_DIRECT    = 6H
_VBE_MEMORY_MODEL_YUV       = 7H

_VBE_ENABLE_FRAMEBUFFER     = (1H shl 00EH)

struct _mode_info_block _mode_attributes*, _wina_attributes*, _winb_attributes*, _win_granularity*, _win_size*, _wina_segment*, _winb_segment*,\
        _win_function*, _bytes_scanline*, _x_resolution*, _y_resolution*, _x_char_size*, _y_char_size*, _number_planes*, _bits_pixel*, _number_blanks*,\
        _memory_model*, _bank_size*, _number_pages*, _red_size*, _red_position*, _green_size*, _green_position*, _blue_size*, _blue_position*,\
        _rsvd_size*, _rsvd_position, _direct_info*, _physical*, _lin_bytes_scanline*, _bank_number_pages*, _lin_number_pages*,\
        _lin_red_size*, _lin_red_position*, _lin_green_size*, _lin_green_position*, _lin_blue_size*, _lin_blue_position*,\
        _lin_rsvd_size*, _lin_rsvd_position*, _max_pixel_clock*
    .mode_attributes:   dw (_mode_attributes)
    .wina_attributes:   db (_wina_attributes)
    .winb_attributes:   db (_winb_attributes)
    .win_granularity:   dw (_win_granularity)
    .win_size:          dw (_win_size)
    .wina_segment:      dw (_wina_segment)
    .winb_segment:      dw (_winb_segment)
    .win_function:      dd (_win_function)
    .bytes_scanline:    dw (_bytes_scanline)
    .x_resolution:      dw (_x_resolution)
    .y_resolution:      dw (_y_resolution)
    .x_char_size:       db (_x_char_size)
    .y_char_size:       db (_y_char_size)
    .number_planes:     db (_number_planes)
    .bits_pixel:        db (_bits_pixel)
    .number_blanks:     db (_number_blanks)
    .memory_model:      db (_memory_model)
    .bank_size:         db (_bank_size)
    .number_pages:      db (_number_pages)
    .reserved_0:        db 0H
    .red_size:          db (_red_size)
    .red_position:      db (_red_position)
    .green_size:        db (_green_size)
    .green_position:    db (_green_position)
    .blue_size:         db (_blue_size)
    .blue_position:     db (_blue_position)
    .rsvd_size:         db (_rsvd_size)
    .rsvd_position:     db (_rsvd_position)
    .direct_info:       db (_direct_info)
    .physical:          dd (_physical)
    .reserved_1:        dd 0H
    .reserved_2:        dw 0H
    .lin_bytes_scanline:dw (_lin_bytes_scanline)
    .bank_number_pages: db (_bank_number_pages)
    .lin_number_pages:  db (_lin_number_pages)
    .lin_red_size:      db (_lin_red_size)
    .lin_red_position:  db (_lin_red_position)
    .lin_green_size:    db (_lin_green_size)
    .lin_green_position:db (_lin_green_position)
    .lin_blue_size:     db (_lin_blue_size)
    .lin_blue_position: db (_lin_blue_position)
    .lin_rsvd_size:     db (_lin_rsvd_size)
    .lin_rsvd_position: db (_lin_rsvd_position)
    .max_pixel_clock:   dd (_max_pixel_clock)
    .reserved_3:        db 0BDH dup 0H
ends

_MP_FLOATING_POINTER_SIGNATURE = "_MP_"
struct _mp_floating_pointer _signature*, _physical_address*, _length*, _spec_rev*,\
        _checksum*, _mp_feature_1*, _mp_feature_2*
    .signature:         dd (_signature)
    .physical_address:  dd (_physical_address)
    .length:            db (_length)
    .spec_rev:          db (_spec_rev)
    .checksum:          db (_checksum)
    .mp_feature_1:      db (_mp_feature_1)
    .mp_feature_2:      db (_mp_feature_2)
    .mp_feature_3:      db 0H
    .mp_feature_4:      db 0H
    .mp_feature_5:      db 0H
ends

_mp_floating_pointer_base: dd (not 0H)

struct _mp_configuration_table _signature*, _base_length*, _spec_rev*, _checksum*, _oem_id*,\
        _product_id*, _oem_table*, _oem_length*, _entry_count*, _local_apic*, _extended_length*, _extended_checksum*
    .signature:         dd (_signature)
    .base_length:       dw (_base_length)
    .spec_rev:          db (_spec_rev)
    .checksum:          db (_checksum)
    .oem_id:            dq (_oem_id)
    .product_id:        dq ((_product_id) and 0FFFFFFFFFFFFFFFFH)
                        dd ((_product_id) shr 040H)
    .oem_table:         dd (_oem_table)
    .oem_length:        dw (_oem_length)
    .entry_count:       dw (_entry_count)
    .local_apic:        dd (_local_apic)
    .extended_length:   dw (_extended_length)
    .extended_checksum: db (_extended_checksum)
    .reserved:          db 0H
ends

_PROCESSOR_ENTRY        = 0H
_BUS_ENTRY              = 1H
_IO_APIC_ENTRY          = 2H
_IO_INTERRUPT_ENTRY     = 3H
_LOCAL_INTERRUPT_ENTRY  = 4H

_PROCESSOR_FLAGS_EN = (1H shl 0H)
_PROCESSOR_FLAGS_BP = (1H shl 1H)
struct _processor_entry _local_apic_id*, _local_apic_version*, _cpu_flags*, _cpu_signature*, _feature_flags*
    .type:              db (_PROCESSOR_ENTRY)
    .local_apic_id:     db (_local_apic_id)
    .local_apic_version:db (_local_apic_version)
    .cpu_flags:         db (_cpu_flags)
    .cpu_signature:     dd (_cpu_signature)
    .feature_flags:     dd (_feature_flags)
    .reserved:          dq 0H
ends

struct _bus_entry _bus_id*, _bus_string*
    .type:              db (_BUS_ENTRY)
    .bus_id:            db (_bus_id)
    .bus_string:        dd ((_bus_string) and 0FFFFFFFFH)
                        dw ((_bus_string) shr 020H)
ends

_IO_APIC_FLAGS_EN = (1H shl 0H)
struct _io_apic_entry _io_apic_id*, _io_apic_version*, _io_apic_flags*, _io_apic_address*
    .type:              db (_IO_APIC_ENTRY)
    .io_apic_id:        db (_io_apic_id)
    .io_apic_version:   db (_io_apic_version)
    .io_apic_flags:     db (_io_apic_flags)
    .io_apic_address:   dd (_io_apic_address)
ends

_INTERRUPT_INT          = 0H
_INTERRUPT_NMI          = 1H
_INTERRUPT_SMI          = 2H
_INTERRUPT_EXTINT       = 3H
_INTERRUPT_PO           _bitwise 011B, 0H
_INTERRUPT_PO_CONFORM   = 000B ; only relevant when EL = LEVEL, default to low
_INTERRUPT_PO_HIGH      = 001B
_INTERRUPT_PO_LOW       = 011B
_INTERRUPT_EL           _bitwise 011B, 2H
_INTERRUPT_EL_CONFORM   = 000B ; default to edge
_INTERRUPT_EL_EDGE      = 001B
_INTERRUPT_EL_LEVEL     = 011B

_IO_INTERRUPT_FLAGS_PO = (1H shl 0H)
_IO_INTERRUPT_FLAGS_EL = (1H shl 1H)
struct _io_interrupt_entry _interrupt_type*, _io_interrupt_flags*, _source_bus_id*,\
        _source_bus_irq*, _destination_io_apic_id*, _destination_io_apic_intin*
    .type:                      db (_IO_INTERRUPT_ENTRY)
    .interrupt_type:            db (_interrupt_type)
    .io_interrupt_flags:        dw (_io_interrupt_flags)
    .source_bus_id:             db (_source_bus_id)
    .source_bus_irq:            db (_source_bus_irq)
    .destination_io_apic_id:    db (_destination_io_apic_id)
    .destination_io_apic_intin: db (_destination_io_apic_intin)
ends

_LOCAL_INTERRUPT_FLAGS_PO = (1H shl 0H)
_LOCAL_INTERRUPT_FLAGS_EL = (1H shl 1H)
struct _local_interrupt_entry _interrupt_type*, _io_interrupt_flags*, _source_bus_id*,\
        _source_bus_irq*, _destination_local_apic_id*, _destination_local_apic_lintin*
    .type:                          db (_LOCAL_INTERRUPT_ENTRY)
    .interrupt_type:                db (_interrupt_type)
    .local_interrupt_flags:         dw (_io_interrupt_flags)
    .source_bus_id:                 db (_source_bus_id)
    .source_bus_irq:                db (_source_bus_irq)
    .destination_local_apic_id:     db (_destination_local_apic_id)
    .destination_local_apic_lintin: db (_destination_local_apic_lintin)
ends

struct _mp_predicate _procentry*, _busentry*, _ioapicentry*, _iointentry*, _lcintentry*
    .procentry:     dd (_procentry)
    .busentry:      dd (_busentry)
    .ioapicentry:   dd (_ioapicentry)
    .iointentry:    dd (_iointentry)
    .lcintentry:    dd (_lcintentry)
ends
assert (((_mp_predicate.procentry shr 2H) = _PROCESSOR_ENTRY) & ((_mp_predicate.busentry shr 2H) = _BUS_ENTRY) &\
    ((_mp_predicate.ioapicentry shr 2H) = _IO_APIC_ENTRY) & ((_mp_predicate.iointentry shr 2H) = _IO_INTERRUPT_ENTRY) &\
    ((_mp_predicate.lcintentry shr 2H) = _LOCAL_INTERRUPT_ENTRY))

_RSDP_MAGIC = "RSD PTR "
struct _rsdp_descriptor_1 _signature*, _checksum*, _oemid*, _revision*, _rsdt_address*
    .signature:         dq (_signature)
    .checksum:          db (_checksum)
    .oemid:             dd ((_oemid) and 0FFFFFFFFH)
                        dw ((_oemid) shr 020H) 
    .revision:          db (_revision)
    .rsdt_address:      dd (_rsdt_address)
ends

struct _rsdp_descriptor_2 _signature*, _checksum*, _oemid*, _revision*, _rsdt_address*,\
        _length*, _xsdt_address*, _extended_checksum*
    .first_part         _rsdp_descriptor_1 _signature, _checksum, _oemid, _revision, _rsdt_address
    .length:            dd (_length)
    .xsdt_address:      dq (_xsdt_address)
    .extended_checksum: db (_extended_checksum)
    .reserved:          db 3H dup 0H
ends

_rsdp_descriptor_base: dd (not 0H)

page_table _default_directory_mapping
    PT_pe _default_table_mapping, (_PE_PRESENT or _PE_READ_WRITE)
    PT_pe _default_table_mapping, (_PE_PRESENT or _PE_READ_WRITE), (_KERNEL_VIRTUAL shr _PAGE_DIRECTORY_SHIFT)
end page_table

page_table _default_table_mapping
    repeat _TABLE_ENTRY_COUNT
        PT_pe ((0H shl _PAGE_DIRECTORY_SHIFT) + ((% - 1H) shl _PAGE_TABLE_SHIFT)), (_PE_PRESENT or _PE_READ_WRITE)
    end repeat
end page_table

; 1th gen paging

page_table _page_directory
    rept 080H i:1H { PT_pe _identity_page_table_#i, _PE_PRESENT or _PE_READ_WRITE }
    PT_pe _kernel_page_table, _PE_PRESENT or _PE_READ_WRITE, _KERNEL_VIRTUAL_INDEX
    PT_null _TEMP_1_INDEX
    PT_null
    PT_pe _page_directory, _PE_PRESENT or _PE_READ_WRITE
end page_table

page_table _kernel_page_table
    repeat _TABLE_ENTRY_COUNT
        PT_pe ((0H shl _PAGE_DIRECTORY_SHIFT) + ((% - 1H) shl _PAGE_TABLE_SHIFT)), _PE_PRESENT or _PE_READ_WRITE
    end repeat
end page_table

rept 080H i:1H
{
    page_table _identity_page_table_#i
        repeat _TABLE_ENTRY_COUNT
            PT_pe (((i - 1H) shl _PAGE_DIRECTORY_SHIFT) + ((% - 1H) shl _PAGE_TABLE_SHIFT)), _PE_PRESENT or _PE_READ_WRITE
        end repeat
    end page_table
}

; 2th gen paging PAE

page_table _pdpt, 1H
    PT_pe _pae_directory_identity, _PE_PRESENT
    PT_pe _pae_empty_1, _PE_PRESENT
    PT_pe _pae_empty_2, _PE_PRESENT
    PT_pe _pae_directory_kernel, _PE_PRESENT
    PT_pe _pdpt, (_PTE_PAT or _PE_READ_WRITE or _PE_PRESENT)
end page_table

rept 080H i:1H
{
    page_table _pae_table_identity_#i, 1H
        repeat _PAE_TABLE_ENTRY_COUNT
            PT_pe (((i - 1H) shl _PAE_PAGE_DIRECTORY_SHIFT) + ((% - 1H) shl _PAGE_TABLE_SHIFT)), _PE_READ_WRITE or _PE_PRESENT
        end repeat
    end page_table
}

page_table _pae_directory_identity, 1H
    rept 080H i:1H { PT_pe _pae_table_identity_#i, _PE_USER or _PE_READ_WRITE or _PE_PRESENT }
end page_table

page_table _pae_empty_1, 1H
end page_table

page_table _pae_empty_2, 1H
end page_table

page_table _pae_directory_kernel, 1H
    PT_pe _pae_table_kernel_1, _PE_READ_WRITE or _PE_PRESENT
    PT_pe _pae_table_kernel_2, _PE_READ_WRITE or _PE_PRESENT
    PT_null _PAE_TEMP_1_INDEX
    PT_null 
    PT_null
    PT_null
    PT_null
    PT_pe _pae_directory_kernel, _PE_READ_WRITE or _PE_PRESENT
    PT_pe _pdpt, _PE_READ_WRITE or _PE_PRESENT
end page_table

rept 2H i:1H
{
    page_table _pae_table_kernel_#i, 1H
        repeat _PAE_TABLE_ENTRY_COUNT
            PT_pe (((i - 1H) shl _PAE_PAGE_DIRECTORY_SHIFT) + ((% - 1H) shl _PAGE_TABLE_SHIFT)), _PE_USER or _PE_READ_WRITE or _PE_PRESENT
        end repeat
    end page_table
}

; Real identity mapping

_VIRTUAL_REAL_PROTECTION = (_PE_USER or _PE_READ_WRITE or _PE_PRESENT)

page_table _pae_real_pgdir, 1H
    PT_pe _pae_real_pgtable, _VIRTUAL_REAL_PROTECTION
end page_table

macro _real_identity _wraparound*
{
    local _items, _overflow
    _overflow = 020H
    _items = (0100000H shr _PAGE_TABLE_SHIFT)
    if (~(_wraparound))
        _items = (_items + _overflow)
    end if
    repeat (_items)
        PT_pe (01000H * (% - 1H)), _VIRTUAL_REAL_PROTECTION
    end repeat
    if (_wraparound)
        repeat (_overflow)
            PT_pe (01000H * (% - 1H)), _VIRTUAL_REAL_PROTECTION
        end repeat
    end if
}

page_table _pae_real_pgtable, 1H
    _real_identity 0H
end page_table

page_table _real_pgtable
    _real_identity 0H
end page_table

_kernel_magic: dd 0H

_kernel_disable_nmi:
    mov al, _CMOS_DISABLE_NMI
    out _CMOS_SELECT, al
    ret

_kernel_enable_nmi:
    xor al, al
    out _CMOS_SELECT, al
    ret

_kernel_setup_paging:
 ; in:
 ;  eax - cr4 flags
 ;  ebx - paging structure
    mov edx, cr0
    and edx, (not _CR0_PG)
    mov cr0, edx
    mov cr4, eax
    mov cr3, ebx
    mov edx, cr0
    or edx, _CR0_PG
    mov cr0, edx
    ret

_kernel_start:
    mov dword [_kernel_magic], eax
    call _kernel_disable_nmi
_kernel_setup:
    org (_KERNEL_VIRTUAL + _kernel_setup)
    mov esi, _default_directory_mapping
    mov cr3, esi
    mov esi, cr0
    or esi, (_CR0_PG or _CR0_WP); or _CR0_MP or _CR0_NE)
    and esi, (not (_CR0_CD or _CR0_NW or _CR0_AM or _CR0_TS or _CR0_EM))
    mov cr0, esi
    wbinvd
    mov edi, _kernel_setup_linear
    jmp edi ; clear prefetch queue
_kernel_setup_linear:
    cmp dword [_kernel_magic], _GRUB1_MULTIBOOT
    jnz _kernel_setup_error
    mov eax, dword [ebx+_multiboot_info.flags]
    test eax, _MULTIBOOT_MEM
    jz _kernel_setup_error
    mov ecx, dword [ebx+_multiboot_info.mem_upper]
    add ecx, dword [ebx+_multiboot_info.mem_lower]
    shr ecx, 2H
    mov dword [_memory_size], ecx
    mov eax, _frame
    mov ebx, dword [_frame.next]
    xor edx, edx
    mov edi, _BITMAP_SET
    call _bitmap_update
_kernel_setup_find_mp_floating_pointer:
    mov eax, _MP_FLOATING_POINTER_SIGNATURE
    xor edi, edi
_kernel_setup_find_mp_floating_pointer_loop:
    scasd
    jz _kernel_setup_save
    add edi, (010H - 4H)
    cmp edi, 0100000H
    jae _kernel_setup_continue
    jmp _kernel_setup_find_mp_floating_pointer_loop
_kernel_setup_save:
    lea edi, [edi-4H]
    mov dword [_mp_floating_pointer_base], edi
_kernel_setup_continue:
    mov esi, _singleton
    call _cpuid_detection
    test byte [_singleton.apic], 1H
    jz _kernel_setup_feature
    mov ecx, _IA32_APIC_BASE
    rdmsr
    or eax, _APIC_BASE_EN
    wrmsr
_kernel_setup_feature:
    mov eax, cr4
    or eax, (_CR4_PSE or _CR4_PGE or _CR4_PCE or _CR4_DE)
    and eax, (not _CR4_TSD)
    test byte [_singleton.fxsr], 1H
    jz $+5H
    or eax, _CR4_OSFXSR
    test byte [_singleton.sse], 1H
    jz $+5H
    or eax, _CR4_OSXMMEXCPT
    test byte [_singleton.xsave], 1H
    jz _kernel_setup_security
    or eax, _CR4_OSXSAVE
    inc byte [_singleton.osxsave]
_kernel_setup_security:
  if (_UMIP_ALLOW)
    test byte [_singleton.umip], 1H
    jz $+5H
    or eax, _CR4_UMIP
  end if
    test byte [_singleton.smap], 1H
    jz $+5H
    or eax, _CR4_SMAP
    test byte [_singleton.smep], 1H
    jz $+5H
    or eax, _CR4_SMEP
    test byte [_singleton.pae], 1H
    jz $+5H
    or eax, _CR4_PAE
    test byte [_singleton.vme], 1H
    jz $+5H
    or eax, _CR4_VME
    test byte [_singleton.mce], 1H
    jz $+5H
    or eax, _CR4_MCE
    mov ebx, (_page_directory or _MEMORY_WB)
    test byte [_singleton.pae], 1H
    jz $+7H
    mov ebx, (_pdpt or _MEMORY_WB)
    mov esi, _kernel_setup_paging
    call esi
    test byte [_singleton.pat], 1H
    jz _kernel_setup_mtrr
    mov ecx, _IA32_CR_PAT
    rdmsr
    mov eax, ((_PAT_UCM shl _PAT_PA3) or (_PAT_UC shl _PAT_PA2) or (_PAT_WT shl _PAT_PA1) or (_PAT_WB shl _PAT_PA0))
    mov edx, ((_PAT_WC shl (_PAT_PA5 shr 020H)) or (_PAT_WP shl (_PAT_PA4 shr 020H)))
    wrmsr
_kernel_setup_mtrr:
    test byte [_singleton.mtrr], 1H
    jz _kernel_setup_launch
    mov ecx, _MTRR_CAP
    rdmsr
    test eax, _MTRR_CAP_FIX
    jz $+8H
    inc byte [_singleton.fixmtrr]
    test eax, _MTRR_CAP_WC
    jz $+8H
    inc byte [_singleton.wc]
    test eax, _MTRR_CAP_SMRR
    jz $+8H
    inc byte [_singleton.smrr]
    and eax, _MTRR_CAP_VCNT_MASK
    mov byte [_singleton.varmtrr], al
    mov ecx, _MTRR_DEF_TYPE
    rdmsr
    mov eax, (_MTRR_DEF_TYPE_E or _MTRR_TYPE_WB)
    test byte [_singleton.fixmtrr], 1H
    jz $+5H
    or eax, _MTRR_DEF_TYPE_FE
    wrmsr
_kernel_setup_launch:
    jmp _kernel_entry
_kernel_setup_error:
    hlt
    jmp _kernel_setup_error

include "kernel.inc"

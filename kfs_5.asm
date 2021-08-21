
_KERNEL_START = 0A00000H
assert (~(_KERNEL_START and _PAGE_OFFSET_MASK))

format ELF executable 3H at _KERNEL_START
entry _kernel_etablish
use32

_kernel_start:

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

_MP_FLOATING_POINTER = "_MP_"
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

_mp_floating_pointer_base: dd 0H
_mp_floating_pointer_found: db 0H

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

irp _kind, io,local
{
    struct _#_kind#_interrupt_entry _interrupt_type*, _#_kind#_interrupt_flags*, _source_bus_id*,\
            _source_bus_irq*, _destination_#_kind#_apic_id*, _destination_#_kind#_apic_intin*
        .type:                              db (_IO_INTERRUPT_ENTRY)
        .interrupt_type:                    db (_interrupt_type)
        .#_kind#_interrupt_flags:           dw (_#_kind#_interrupt_flags)
        .source_bus_id:                     db (_source_bus_id)
        .source_bus_irq:                    db (_source_bus_irq)
        .destination_#_kind#_apic_id:       db (_destination_#_kind#_apic_id)
        .destination_#_kind#_apic_intin:    db (_destination_#_kind#_apic_intin)
    ends_
}

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

_RSDP = "RSD PTR "
struct _rsdp_descriptor _signature*, _checksum*, _oemid*, _revision*, _rsdt_address*
    .signature:         dq (_signature)
    .checksum:          db (_checksum)
    .oemid:             dd ((_oemid) and 0FFFFFFFFH)
                        dw ((_oemid) shr 020H) 
    .revision:          db (_revision)
    .rsdt_address:      dd (_rsdt_address)
ends

struct _rsdp_descriptor_extended _signature*, _checksum*, _oemid*, _revision*, _rsdt_address*,\
        _length*, _xsdt_address*, _extended_checksum*
    .legacy             _rsdp_descriptor _signature, _checksum, _oemid, _revision, _rsdt_address
    .length:            dd (_length)
    .xsdt_address:      dq (_xsdt_address)
    .extended_checksum: db (_extended_checksum)
    .reserved:          db 3H dup 0H
ends

_rsdp_descriptor_base: dd 0H
_rsdp_descriptor_found: db 0H

struct _acpi_sdt_header _signature*, _length*, _revision*, _checksum*, _oem_id*, _oem_table_id*,\
        _oem_revision*, _creator_id*, _creator_revision*
    .signature:         dd (_signature)
    .length:            dd (_length)
    .revision:          db (_revision)
    .checksum:          db (_checksum)
    .oem_id:            dd ((_oem_id) and 0FFFFFFFFH)
                        dw ((_oem_id) shr 020H)
    .oem_table_id:      dq (_oem_table_id)
    .oem_revision:      dd (_oem_revision)
    .creator_id:        dd (_creator_id)
    .creator_revision:  dd (_creator_revision)
ends

_PCAT_COMPAT = (1H shl 0H)
struct _madt_header _signature*, _length*, _revision*, _checksum*, _oem_id*, _oem_table_id*,\
        _oem_revision*, _creator_id*, _creator_revision*, _local_apic*, _flags*
    .common             _acpi_sdt_header _signature, _length, _revision, _checksum, _oem_id, _oem_table_id,\
                            _oem_revision, _creator_id, _creator_revision
    .local_apic:        dd (_local_apic)
    .flags:             dd (_flags)
ends

enum _MADT_PROCESSOR_LOCAL_APIC, _MADT_IO_APIC, _MADT_INTERRUPT_OVERRIDE, _MADT_NMI, _MADT_LOCAL_APIC_NMI,\
    _MADT_LOCAL_APIC_OVERRIDE, _MADT_IO_SAPIC, _MADT_LOCAL_SAPIC, _MADT_PLATFORM_INTERRUPT, _MADT_PROCESSOR_LOCAL_X2APIC,\
    _MADT_LOCAL_X2APIC_NMI, _MADT_GICC, _MADT_GICD, _MADT_MSI, _MADT_GICR, _MADT_ITS

struct _madt_prefix _type*, _length*
    .type:      db (_type)
    .length:    db (_length)
ends

_MADT_LOCAL_APIC_FLAGS_ENABLED          = (1H shl 0H)
_MADT_LOCAL_APIC_FLAGS_ONLINE_CAPABLE   = (1H shl 1H)
struct _madt_processor_local_apic _length*, _acpi_id*, _apic_id*, _flags*
    .prefix     _madt_prefix _MADT_PROCESSOR_LOCAL_APIC, (_length)
    .acpi_id:   db (_acpi_id)
    .apic_id:   db (_apic_id)
    .flags:     dd (_flags)
ends

struct _madt_io_apic _length*, _io_apic_id*, _io_apic_address*, _gsi_base*
    .prefix             _madt_prefix _MADT_IO_APIC, (_length)
    .io_apic_id:        db (_io_apic_id)
    .reserved:          db 0H
    .io_apic_address:   dd (_io_apic_address)
    .gsi_base:          dd (_gsi_base)
ends

struct _madt_interrupt_override _length*, _bus*, _irq*, _gsi*, _flags*
    .type:      db (_MADT_INTERRUPT_OVERRIDE)
    .length:    db (_length)
    .bus:       db (_bus)
    .irq:       db (_irq)
    .gsi:       dd (_gsi)
    .flags:     dw (_flags)
ends

struct _madt_nmi _length*, _flags*, _gsi*
    .type:      db (_MADT_NMI)
    .length:    db (_length)
    .flags:     dw (_flags)
    .gsi:       dd (_gsi)
ends

struct _madt_local_apic_nmi _length*, _apic_id*, _flags*, _lint*
    .type:      db (_MADT_LOCAL_APIC_NMI)
    .length:    db (_length)
    .acpi_id:   db (_apic_id)
    .flags:     dw (_flags)
    .lint:      db (_lint)
ends

struct _matd_local_apic_override _length*, _local_apic_address*
    .type:                  db (_MADT_LOCAL_APIC_OVERRIDE)
    .length:                db (_length)
    .reserved:              db 0H
    .local_apic_address:    dd (_local_apic_address)
ends

struct _madt_io_sapic _length*, _io_sapic_id*, _gsi_base*, _io_sapic_address*
    .type:              db (_MADT_IO_SAPIC)
    .length:            db (_length)
    .io_sapic_id:       db (_io_sapic_id)
    .reserved:          db 0H
    .gsi_base:          dd (_gsi_base)
    .io_sapic_address:  dq (_io_sapic_address)
ends

struct _madt_local_sapic _length*, _acpi_id*, _local_sapic_id*, _local_sapic_eid*, _flags*, _acpi_uid_value*
    .type:              db (_MADT_LOCAL_SAPIC)
    .length:            db (_length)
    .acpid_id:          db (_acpi_id)
    .local_sapic_id:    db (_local_sapic_id)
    .local_sapic_eid:   db (_local_sapic_eid)
    .reserved:          db 0H dup 3H
    .flags:             dd (_flags)
    .acpi_uid_value:    dd (_acpi_uid_value)
    .acpi_uid_string:
ends

struct _madt_platform_interrupt _length*, _flags*, _processor_id*, _processor_eid*, _io_sapic_vector*, _gsi*
    .type:              db (_MADT_PLATFORM_INTERRUPT)
    .length:            db (_length)
    .flags:             dw (_flags)
    .interrupt_type:
    .processor_id:      db (_processor_id)
    .processor_eid:     db (_processor_eid)
    .io_sapic_vector:   db (_io_sapic_vector)
    .gsi:               dd (_gsi)
ends

_RSDT = "RSDT"
_MADT = "APIC"
_BERT = "BERT"
_CPEP = "CPEP"
_DSDT = "DSDT"
_ECDT = "ECDT"
_EINJ = "EINJ"
_ERST = "ERST"

_KERNEL_IDENTITY = (_KERNEL_START + _kernel_size)
if (_KERNEL_IDENTITY and (_PSE_PAGE_FRAME_SIZE - 1H))
    _KERNEL_IDENTITY = (_KERNEL_IDENTITY + _PSE_PAGE_FRAME_SIZE)
end if
_KERNEL_IDENTITY = (_KERNEL_IDENTITY / _PSE_PAGE_FRAME_SIZE)
if (~(_KERNEL_IDENTITY))
    _KERNEL_IDENTITY = 1H
end if

_PAE_KERNEL_IDENTITY = (_KERNEL_IDENTITY * (_TABLE_ENTRY_COUNT / _PAE_TABLE_ENTRY_COUNT))

_page_table _default_directory_mapping
  repeat _KERNEL_IDENTITY
    PT_pe (_default_table_mapping + ((% - 1H) * _PAGE_FRAME_SIZE)), (_PE_PRESENT or _PE_READ_WRITE)
  end repeat
  PT_pe _default_table_mapping, (_PE_PRESENT or _PE_READ_WRITE), (_KERNEL_VIRTUAL shr _PAGE_DIRECTORY_SHIFT)
  repeat (_KERNEL_IDENTITY - 1H)
    PT_pe (_default_table_mapping + (% * _PAGE_FRAME_SIZE)), (_PE_PRESENT or _PE_READ_WRITE)
  end repeat
end _page_table

_default_table_mapping:

repeat _KERNEL_IDENTITY
  _index = (% - 1H)
  rept _TABLE_ENTRY_COUNT i:0H
    { _PT_pe ((_index shl _PAGE_DIRECTORY_SHIFT) + ((i) shl _PAGE_TABLE_SHIFT)), (_PE_READ_WRITE or _PE_PRESENT) }
end repeat

; 1th gen paging

;page_table _page_directory
;    rept 080H i:1H { PT_pe _identity_page_table_#i, _PE_PRESENT or _PE_READ_WRITE }
;    PT_pe _kernel_page_table, _PE_PRESENT or _PE_READ_WRITE, _KERNEL_VIRTUAL_INDEX
    ;PT_null _TEMP_1_INDEX
    ;T_null
;    PT_pe _page_directory, _PE_PRESENT or _PE_READ_WRITE
;end page_table

;page_table _kernel_page_table
    ;repeat _TABLE_ENTRY_COUNT
    ;    PT_pe ((0H shl _PAGE_DIRECTORY_SHIFT) + ((% - 1H) shl _PAGE_TABLE_SHIFT)), _PE_PRESENT or _PE_READ_WRITE
    ;end repeat
;end page_table

;rept 080H i:1H
;{
;    page_table _identity_page_table_#i
    ;    repeat _TABLE_ENTRY_COUNT
   ;         PT_pe (((i - 1H) shl _PAGE_DIRECTORY_SHIFT) + ((% - 1H) shl _PAGE_TABLE_SHIFT)), _PE_PRESENT or _PE_READ_WRITE
   ;     end repeat
;    end page_table
;}

; 2th gen paging PAE

;page_table _pdpt, 1H
;    PT_pe _pae_directory_identity, _PE_PRESENT
;    PT_pe _pae_empty_1, _PE_PRESENT
;    PT_pe _pae_empty_2, _PE_PRESENT
;    PT_pe _pae_directory_kernel, _PE_PRESENT
;    PT_pe _pdpt, (_PTE_PAT or _PE_READ_WRITE or _PE_PRESENT)
;end page_table

;rept 080H i:1H
;{
;    page_table _pae_table_identity_#i, 1H
;        repeat _PAE_TABLE_ENTRY_COUNT
;            PT_pe (((i - 1H) shl _PAE_PAGE_DIRECTORY_SHIFT) + ((% - 1H) shl _PAGE_TABLE_SHIFT)), \
;                _PE_READ_WRITE or _PE_PRESENT
;        end repeat
;    end page_table
;}

;page_table _pae_directory_identity, 1H
;    rept 080H i:1H { PT_pe _pae_table_identity_#i, _PE_USER or _PE_READ_WRITE or _PE_PRESENT }
;end page_table

;page_table _pae_empty_1, 1H
;end page_table

;page_table _pae_empty_2, 1H
;end page_table

;page_table _pae_directory_kernel, 1H
;    PT_pe _pae_table_kernel_1, _PE_READ_WRITE or _PE_PRESENT
;    PT_pe _pae_table_kernel_2, _PE_READ_WRITE or _PE_PRESENT
;    PT_null _PAE_TEMP_1_INDEX
;    PT_null 
;    PT_null
;    PT_null
;    PT_null
;    PT_pe _pae_directory_kernel, _PE_READ_WRITE or _PE_PRESENT
;    PT_pe _pdpt, _PE_READ_WRITE or _PE_PRESENT
;end page_table

;rept 2H i:1H
;{
;    page_table _pae_table_kernel_#i, 1H
;        repeat _PAE_TABLE_ENTRY_COUNT
;            PT_pe (((i - 1H) shl _PAE_PAGE_DIRECTORY_SHIFT) + ((% - 1H) shl _PAGE_TABLE_SHIFT)),\
;                _PE_USER or _PE_READ_WRITE or _PE_PRESENT
;        end repeat
;    end page_table
;}

; Real identity mapping

_VIRTUAL_REAL_PROTECTION = (_PE_USER or _PE_READ_WRITE or _PE_PRESENT)

_page_table _pae_real_pgdir, pae
    PT_pe _pae_real_pgtable, _VIRTUAL_REAL_PROTECTION
end _page_table

macro _real_identity _wraparound*
{
    local _items, _overflow
    _overflow = 020H
    _items = (_FIRST_MEGABYTE shr _PAGE_TABLE_SHIFT)
    if (~(_wraparound))
        _items = (_items + _overflow)
    end if
    repeat (_items)
        PT_pe (_PAGE_FRAME_SIZE * (% - 1H)), _VIRTUAL_REAL_PROTECTION
    end repeat
    if (_wraparound)
        repeat (_overflow)
            PT_pe (_PAGE_FRAME_SIZE * (% - 1H)), _VIRTUAL_REAL_PROTECTION
        end repeat
    end if
}

_page_table _pae_real_pgtable, pae
    _real_identity 0H
end _page_table

_page_table _real_pgtable
    _real_identity 0H
end _page_table

_kernel_magic: dd 0H

_kernel_disable_nmi:
    mov al, _CMOS_DISABLE_NMI
    out _CMOS_SELECT, al
    ret

_kernel_enable_nmi:
    xor al, al
    out _CMOS_SELECT, al
    ret

_kernel_reset_fpu:
    ret

_zero_checksum_check:
 ; in:
 ;  ecx - count of byte to add
 ;  edi - base struct pointer
 ; out: cf - set when the sum does not equal to 0H
 ; preserves: ebx, edx, esi, edi, ebp
    xor al, al
    add al, byte [edi+ecx-1H]
    loop _zero_checksum_check+2H
    test al, al
    jz $+3H
    stc
    ret

_mp_floating_checksum:
    movzx ecx, byte [edi+_mp_floating_pointer.length]
    shl ecx, 4H
    jmp _zero_checksum_check

_acpi_rsdp_checksum:
 ; note: revision = 0H when ACPI 1.0 is present, otherwise it's 2H for subsequent version
    xor ecx, ecx
    mov cl, _rsdp_descriptor.sizeof
    cmp byte [edi+_rsdp_descriptor.revision], 0H
    jz _zero_checksum_check
    mov cl, _rsdp_descriptor_extended.sizeof
    cmp byte [edi+_rsdp_descriptor.revision], 2H
    jz _zero_checksum_check
    stc
    ret

_acpi_sdt_checksum:
    mov ecx, dword [edi+_acpi_sdt_header.length]
    jmp _zero_checksum_check

_kernel_find_table:
 ; in:
 ;  eax - first part magic number
 ;  ebx - destination base pointer
 ;  ecx - how to treat edx
 ;  edx - second part magic number (if ecx = (not 0H))
 ;  esi - functor to check checksum  (must only modify eax,ecx)
 ; preserves: eax, ebx, ecx, edx, esi, ebp
    xor edi, edi
_kernel_find_table_loop:
    scasd
    jnz _kernel_find_table_update
    jecxz _kernel_find_table_save
    cmp edx, dword [edi]    
    jz _kernel_find_table_save
_kernel_find_table_update:
    add edi, (010H - 4H)
    cmp edi, _FIRST_MEGABYTE
    jae _kernel_find_table_exit
    jmp _kernel_find_table_loop
_kernel_find_table_save:
    lea edi, [edi-4H]
    mov dword [ebx], edi
    push eax ecx
    call esi
    pop ecx eax
    lea edi, [edi+4H]
    jc _kernel_find_table_update
_kernel_find_table_exit:
    ret

_store_entry_physical = (_store_entry - _KERNEL_VIRTUAL)

_kernel_1th_paging:
 ; note: (((400H^2H)*4H)+(400H*4H)) to identity map all memory
    mov ecx, _KERNEL_VIRTUAL_INDEX
  assert (_KERNEL_VIRTUAL_INDEX <> 0H)
    mov edi, _FIRST_MEGABYTE
    mov eax, (_FIRST_MEGABYTE + _PAGE_FRAME_SIZE + _PE_READ_WRITE + _PE_PRESENT)
_kernel_1th_paging_pd:
    call _store_entry_physical
    add eax, _PAGE_FRAME_SIZE
    loop _kernel_1th_paging_pd
    mov eax, (_FIRST_MEGABYTE + _PAGE_FRAME_SIZE + _PE_READ_WRITE + _PE_PRESENT)    
    mov cl, _KERNEL_IDENTITY
_kernel_1th_paging_supervisor: ; set the kernel mapping as well as the recursive entry
    call _store_entry_physical
    add eax, _PAGE_FRAME_SIZE
    loop _kernel_1th_paging_supervisor
    mov edi, (_FIRST_MEGABYTE + _PAGE_FRAME_SIZE - 4H)
    mov eax, (_FIRST_MEGABYTE + _PE_READ_WRITE + _PE_PRESENT)
    call _store_entry_physical
    mov ecx, (_KERNEL_VIRTUAL_INDEX * _TABLE_ENTRY_COUNT)
    mov edi, (_FIRST_MEGABYTE + _PAGE_FRAME_SIZE)
    mov eax, (_PE_READ_WRITE + _PE_PRESENT)
_kernel_1th_paging_pt:
    call _store_entry_physical
    add eax, _PAGE_FRAME_SIZE
    loop _kernel_1th_paging_pt
    ret

_kernel_2th_paging:
 ; note: ((((200H^2H)*8H)*4H)+(4H*8H)) to identity map all memory
    mov edi, _FIRST_MEGABYTE
    mov eax, (_FIRST_MEGABYTE + _PAGE_FRAME_SIZE + _PE_PRESENT)
    xor edx, edx
    xor ecx, ecx
    mov cl, _PAE_PDPT_ENTRY_COUNT
_kernel_2th_paging_pdpt:
    call _store_entry_physical
    add eax, _PAGE_FRAME_SIZE
    loop _kernel_2th_paging_pdpt
    mov eax, (_FIRST_MEGABYTE + _PE_READ_WRITE + _PE_PRESENT)
    call _store_entry_physical ; fifth slot technique
    mov ecx, ((_KERNEL_VIRTUAL shr _PAE_PAGE_DIRECTORY_POINTER_SHIFT) * _PAE_TABLE_ENTRY_COUNT)
    mov edi, (_FIRST_MEGABYTE + _PAGE_FRAME_SIZE)
    mov eax, (_FIRST_MEGABYTE + (_PAGE_FRAME_SIZE * (_PAE_PDPT_ENTRY_COUNT + 1H)) + _PE_READ_WRITE + _PE_PRESENT)
_kernel_2th_paging_pd:
    call _store_entry_physical
    add eax, _PAGE_FRAME_SIZE
    loop _kernel_2th_paging_pd
    mov eax, (_FIRST_MEGABYTE + (_PAGE_FRAME_SIZE * (_PAE_PDPT_ENTRY_COUNT + 1H)) + _PE_READ_WRITE + _PE_PRESENT)
    mov cl, _PAE_KERNEL_IDENTITY
_kernel_2th_paging_supervisor:
    call _store_entry_physical
    add eax, _PAGE_FRAME_SIZE
    loop _kernel_2th_paging_supervisor
    mov edi, (_FIRST_MEGABYTE + (_PAGE_FRAME_SIZE * (_PAE_PDPT_ENTRY_COUNT + 1H)) - ((_PAE_PDPT_ENTRY_COUNT + 1H) shl 3H))
    mov eax, (_FIRST_MEGABYTE + _PAGE_FRAME_SIZE + _PE_READ_WRITE + _PE_PRESENT)
    mov cl, _PAE_PDPT_ENTRY_COUNT
_kernel_2th_paging_recursive:
    call _store_entry_physical
    add eax, _PAGE_FRAME_SIZE
    loop _kernel_2th_paging_recursive
    mov eax, (_FIRST_MEGABYTE + _PE_READ_WRITE + _PE_PRESENT)
    call _store_entry_physical
    mov ecx, ((_KERNEL_VIRTUAL shr _PAE_PAGE_DIRECTORY_SHIFT) * _PAE_TABLE_ENTRY_COUNT)
    mov eax, (_PE_READ_WRITE + _PE_PRESENT)
_kernel_2th_paging_pt:
    call _store_entry_physical
    add eax, _PAGE_FRAME_SIZE
    loop _kernel_2th_paging_pt
    ret

_kernel_3th_paging:
    mov edi, _FIRST_MEGABYTE
    mov eax, (_FIRST_MEGABYTE + _PAGE_FRAME_SIZE + _PE_READ_WRITE + _PE_PRESENT)
    xor edx, edx
    call _store_entry_physical
    mov edi, (_FIRST_MEGABYTE + (_PML4_HIGHER_HALF shl 3H))
    call _store_entry_physical
    mov eax, (_FIRST_MEGABYTE + _PE_READ_WRITE + _PE_PRESENT)
    mov edi, (_FIRST_MEGABYTE + ((_PML4_TABLE_ENTRY_COUNT - 1H) shl 3H))
    call _store_entry_physical
    mov eax, (_FIRST_MEGABYTE + (_PAGE_FRAME_SIZE shl 1H) + _PE_READ_WRITE + _PE_PRESENT)
    xor ecx, ecx
    mov cl, 3H
_kernel_3th_paging_pdpt:
    call _store_entry_physical
    add eax, _PAGE_FRAME_SIZE
    loop _kernel_3th_paging_pdpt
    mov edi, (_FIRST_MEGABYTE + (_PAGE_FRAME_SIZE shl 1H))
    mov ecx, (_PAE_TABLE_ENTRY_COUNT * 3H)
_kernel_3th_paging_pd:
    call _store_entry_physical
    add eax, _PAGE_FRAME_SIZE
    loop _kernel_3th_paging_pd
    mov ecx, ((_PAE_TABLE_ENTRY_COUNT shl 1H) * 3H)
    mov eax, (_PE_READ_WRITE + _PE_PRESENT)
_kernel_3th_paging_pt:
    call _store_entry_physical
    add eax, _PAGE_FRAME_SIZE
    loop _kernel_3th_paging_pt
    ret

_kernel_refresh_paging:
 ; in:
 ;  eax - cr4 flags
 ;  ebx - memory cache policy
 ;  esi - predicate to call for paging table setup
    mov edx, cr0
    and edx, (not _CR0_PG)
    mov cr0, edx
    mov cr4, eax
    or ebx, _FIRST_MEGABYTE
    mov cr3, ebx
    call esi
    mov edx, cr0
    or edx, _CR0_PG
    mov cr0, edx
    ret

_descriptor_table __o
    $DT_null
    ;_kernel_code_64_segment DT_dte _DE_L or _DE_G, _DE_PRESENT or _DPL0 or _DE_EXECUTABLE, 0H, 0FFFFFH
    __m DT_dte _DE_L or _DE_G, _DE_PRESENT or _DPL1 or _DE_EXECUTABLE, 01111H, 0FFFFFH
    __w DT_dte _DE_B or _DE_G, _DE_PRESENT or _DPL1 or _DE_WRITABLE, 01111H, 00FFFFFH
    _fs_gs_test DT_dte 0H, _DE_PRESENT, 0H, 0H
end _descriptor_table

__j:
    mov edx, cr0
    and edx, (not _CR0_PG)
    mov cr0, edx
    mov eax, _FIRST_MEGABYTE
    mov cr3, eax
    mov eax, cr4
    or eax, _CR4_PAE
    mov cr4, eax
    mov ecx, _EFER
    rdmsr
    or eax, _EFER_LME or _EFER_SCE
    wrmsr
    mov eax, cr0
    or eax, _CR0_PG
    mov cr0, eax
    _load_descriptor_table gdt, __o
    jmp 8H:__k
    ;pushd __w.selector + _RPL1
    ;pushd 0100H
    ;pushd __m.selector + _RPL1
    ;pushd __k
    ;retfd

__k:
use64
    mov rax, "WELCOME "
    jmp $

    mov ax, _RPL1
    mov ss, ax
    push 0H
    
    mov rax, 0H
    mov cr8, rax    

    mov rax, (_LONG_MODE_CANONICAL or (_PML4_HIGHER_HALF shl _PML4_SHIFT))
    mov rbx, qword [rax]
    mov ax, _fs_gs_test.selector
    mov fs, ax
    mov gs, ax
    mov qword [fs:0H], 050H
    mov ecx, _FS_BASE
    rdmsr
    mov ecx, _KERNEL_GS_BASE
    mov eax, 0C0DEH
    wrmsr
    swapgs
    jmp $

use32

_kernel_etablish:
    mov dword [_kernel_magic], eax
    call _kernel_disable_nmi
_kernel_setup:
    org (_KERNEL_VIRTUAL + _kernel_setup)
    mov esi, _default_directory_mapping
    mov cr3, esi
    mov esi, cr0
    or esi, (_CR0_PG or _CR0_WP) ; or _CR0_MP or _CR0_NE)
    and esi, (not (_CR0_CD or _CR0_NW or _CR0_AM or _CR0_TS or _CR0_EM))
    mov cr0, esi
    wbinvd
    mov edi, _kernel_setup_linear
    jmp edi ; clear prefetch queue
_kernel_setup_linear:
    mov edi, _FIRST_MEGABYTE
    mov ecx, (_KERNEL_START - _FIRST_MEGABYTE)
    call _clear_string
    ;call _kernel_3th_paging
    ;jmp __j
    cmp dword [_kernel_magic], _GRUB1_MULTIBOOT
    jnz _kernel_error
    mov eax, dword [ebx+_multiboot_info.flags]
    test eax, _MULTIBOOT_MEM
    jz _kernel_error
    mov ecx, dword [ebx+_multiboot_info.mem_upper]
    add ecx, dword [ebx+_multiboot_info.mem_lower]
    shr ecx, 2H
    mov dword [_memory_size], ecx
    mov eax, _frame
    mov ebx, dword [_frame.next]
    xor edx, edx
    mov edi, _BITMAP_SET
    call _bitmap_update
    mov eax, _MP_FLOATING_POINTER
    xor ecx, ecx
    mov ebx, _mp_floating_pointer_base
    mov esi, _mp_floating_checksum
    call _kernel_find_table
    setnc byte [_mp_floating_pointer_found]
    mov eax, (_RSDP and 0FFFFFFFFH)
    mov edx, (_RSDP shr 020H)
    not ecx
    mov ebx, _rsdp_descriptor_base
    mov esi, _acpi_rsdp_checksum
    call _kernel_find_table 
    setnc byte [_rsdp_descriptor_found]
    mov esi, _singleton
    call _cpuid_detection
    jc _kernel_error
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
  if (_VMX_ALLOW)
    test byte [_singleton.vmx], 1H
    jz $+5H
    or eax, _CR4_VMXE
  end if
    test byte [_singleton.mce], 1H
    jz $+5H
    or eax, _CR4_MCE
    mov esi, _kernel_1th_paging 
    test byte [_singleton.pae], 1H
    jz $+7H
    mov esi, _kernel_2th_paging 
    xor ebx, ebx
    mov bl, _MEMORY_WB
    call _kernel_refresh_paging
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

_kernel_error_message string "B O O T   E R R O R "
_kernel_error:
    cli
    call _kernel_disable_nmi
    mov esi, _kernel_error_message
    mov edi, _LEGACY_TEXTMODE
    xor ecx, ecx
    mov cl, _kernel_error_message.sizeof
    rep movsb
_kernel_error_hang:
    hlt
    jmp _kernel_error_hang

include "kernel.inc"

_kernel_end:

_kernel_size = ((_kernel_end - _KERNEL_VIRTUAL) - _kernel_start)


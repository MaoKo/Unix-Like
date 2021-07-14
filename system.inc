
macro struct __name*, __argument&
{
    local _multi, _name, _argument, _proxy
    define _multi false
    define _name __name
    match _struc _remain, __name
    \{
        define _multi true
        define _name _struc
        define _proxy _remain,__argument
        match _, __argument \\{ _argument equ _proxy \\}
        match,__argument    \\{ define _argument _remain \\}
    \}
    match =false, _multi \{ define _argument \}
    macro __struct
    \{
        local _arglist
        define _arglist
        match _empty, _argument \\{ irp _, _empty \\\{ _arglist equ _arglist 0H, \\\} \\}
        match,_argument \\{ define _arglist , \\}
        virtual at 0H
            match _struc_name, _name
            \\{
                match _=,, _arglist \\\{ _struc_name _struc_name _ \\\}
                match  =,, _arglist \\\{ _struc_name _struc_name   \\\}
                _struc_name\\#.sizeof = $
                _struc_name\\#.powertwo = $
                if ((_struc_name\\#.powertwo) & ((bsf _struc_name\\#.powertwo) <> (bsr _struc_name\\#.powertwo)))
                    _struc_name\\#.powertwo = (2H shl (bsr _struc_name\\#.powertwo))
                end if
            \\}
        end virtual
        purge __struct
    \}
    match _struc_name, _name \{ irpv _struc_argument, _argument \\{ struc _struc_name _struc_argument \\} \}
    \{
}

ends fix } __struct

macro _itoa number*
{
    local _number, _modulo, _length
    _number = (number)
    if (_number < 0H)
        db 02DH
        _number = (-_number)
    end if
    _length = 0H
    if (~(definite __itoa_virtual))
        virtual at 0H
            __itoa_virtual::
        end virtual
    end if
    assert (_number eqtype 0H)
    while _number
        _modulo = _number mod 010H
        _number = _number / 010H
        _length = _length + 1H
        virtual __itoa_virtual
            if (_modulo >= 00AH)
                db ((_modulo-00AH)+061H)
            else
                db (_modulo+030H)
            end if
        end virtual
    end while
    repeat _length
        virtual __itoa_virtual
            load _number byte from __itoa_virtual:($-(%))
        end virtual
        db _number
    end repeat
}

struc string data*&
{
    .: db data
    .sizeof = ($ - .)
}

macro align _power*, _padding:0H
{
    assert ((bsr (_power)) = (bsf (_power)))
    while ($ mod (_power))
        db (_padding)
    end while
}

_MAX_REAL_ADDRESS = (00FFFF0H + 0FFFFH)

_CR0_PE     = (1H shl 0H)
_CR0_MP     = (1H shl 1H)
_CR0_TS     = (1H shl 3H)
_CR0_WP     = (1H shl 010H)
_CR0_AM     = (1H shl 012H)
_CR0_NW     = (1H shl 01DH)
_CR0_CD     = (1H shl 01EH)
_CR0_PG     = (1H shl 01FH)

_CR4_VME    = (1H shl 0H)
_CR4_PVI    = (1H shl 1H)
_CR4_TSD    = (1H shl 2H)
_CR4_DE     = (1H shl 3H)
_CR4_PSE    = (1H shl 4H)
_CR4_PAE    = (1H shl 5H)
_CR4_PGE    = (1H shl 7H)
_CR4_OSFXSR = (1H shl 9H)
_CR4_UMIP   = (1H shl 00BH)
_CR4_SMEP   = (1H shl 014H)
_CR4_SMAP   = (1H shl 015H)

_DR7_L0     = (1H shl 0H)
_DR7_G0     = (1H shl 1H)
_DR7_L1     = (1H shl 2H)
_DR7_G1     = (1H shl 3H)
_DR7_L2     = (1H shl 4H)
_DR7_G2     = (1H shl 5H)
_DR7_L3     = (1H shl 6H)
_DR7_G3     = (1H shl 7H)
_DR7_LE     = (1H shl 8H)
_DR7_GE     = (1H shl 9H)
_DR7_GD     = (1H shl 00DH)
_DR7_RW0    = 010H
_DR7_LEN0   = 012H
_DR7_RW1    = 014H
_DR7_LEN1   = 016H
_DR7_RW2    = 018H
_DR7_LEN2   = 01AH
_DR7_RW3    = 01CH
_DR7_LEN3   = 01EH

_DR6_B0 = (1H shl 0H)
_DR6_B1 = (1H shl 1H)
_DR6_B2 = (1H shl 2H)
_DR6_B3 = (1H shl 3H)
_DR6_BD = (1H shl 00DH)
_DR6_BS = (1H shl 00EH)
_DR6_BT = (1H shl 00FH)

_DEBUG_LEN_1B = 000B
_DEBUG_LEN_2B = 001B
_DEBUG_LEN_4B = 011B
_DEBUG_LEN_8B = 010B

_DEBUG_RW_INST_READ = 000B
_DEBUG_RW_DATA_WRITE = 001B
_DEBUG_RW_IO_READ_WRITE = 010B
_DEBUG_RW_DATA_READ_WRITE = 011B

macro __transform_struc [_item*] { forward struc _item _param& \{ _item _param \} }

_TABLE_ENTRY_COUNT                  = 400H
_PAE_TABLE_ENTRY_COUNT              = 200H
_PAE_PDPT_ENTRY_COUNT               = 4H
_PAGING_LEVEL_BIT                   = ((bsf _TABLE_ENTRY_COUNT) shl 1H)
_PAE_PAGING_LEVEL_BIT               = ((bsf _PAE_PDPT_ENTRY_COUNT) + ((bsf _PAE_TABLE_ENTRY_COUNT) shl 1H))
_PAGE_FRAME_SIZE                    = (_TABLE_ENTRY_COUNT shl 2H)
_PAGE_OFFSET_MASK                   = 00FFFH
_PAGE_FLAGS_MASK                    = _PAGE_OFFSET_MASK
_PAGE_OFFSET_MASK_PDE_PAT           = 01FFFH
_PAGE_TABLE_SHIFT                   = 00CH
_PAE_PAGE_TABLE_SHIFT               = _PAGE_TABLE_SHIFT
_PAE_FLAGS_UPPER_MASK               = (_PAE_XD shr 020H)
_PAE_LONG_POINTER_UPPER             = (_PAGE_OFFSET_MASK shl _PAE_PAGING_LEVEL_BIT)
_PAGE_DIRECTORY_SHIFT               = 016H
_PSE_PAGE_FRAME_SIZE                = (1H shl _PAGE_DIRECTORY_SHIFT)
_PSE_OFFSET_MASK                    = (_PSE_PAGE_FRAME_SIZE - 1H)
_PAE_POINTER_PAGE_COUNT             = (_PAE_TABLE_ENTRY_COUNT * _PAE_TABLE_ENTRY_COUNT)
_PAE_PAGE_DIRECTORY_SHIFT           = 015H
_PAE_PSE_PAGE_FRAME_SIZE            = (1H shl _PAE_PAGE_DIRECTORY_SHIFT)
_PAE_PSE_OFFSET_MASK                = (_PAE_PSE_PAGE_FRAME_SIZE - 1H)
_PAE_PAGE_DIRECTORY_POINTER_SHIFT   = 01EH
_PAGE_DIRECTORY_MASK                = 0FFC00000H
_PAGE_TABLE_MASK                    = 0003FF000H
_PAE_PAGE_DIRECTORY_POINTER_MASK    = 0C0000000H
_PAE_PAGE_DIRECTORY_MASK            = 03FE00000H
_PAE_PAGE_TABLE_MASK                = 0001FF000H

_MEMORY_WB       = 0H
_MEMORY_WT       = (_PE_PWT)
_MEMORY_UC       = (_PE_PCD)
_MEMORY_UCM      = (_PE_PCD or _PE_PWT)
_MEMORY_WP       = (_PTE_PAT)
_MEMORY_WP       = (_PDE_PS_PAT or _PTE_PAT)
_MEMORY_WC       = ((_PDE_PS_PAT or _PTE_PAT) or _PE_PWT)

_PE_PRESENT     = (1H shl 0H)
_PE_READ_WRITE  = (1H shl 1H)
_PE_USER        = (1H shl 2H)
_PE_PWT         = (1H shl 3H)
_PE_PCD         = (1H shl 4H)
_PE_ACCESS      = (1H shl 5H)
_PE_DIRTY       = (1H shl 6H)
_PTE_PAT        = (1H shl 7H)
_PDE_SIZE       = (1H shl 7H)
_PE_GLOBAL      = (1H shl 8H)
_PE_COW         = (1H shl 9H)
_PE_RDO         = (1H shl 00AH)
_PE_IS_PDE      = (1H shl 00BH)
_PDE_PS_PAT     = (1H shl 00CH)
_PAE_XD         = (1H shl 03FH)
_PE_NULL        = 0H

_PF_P           = 001H
_PF_RW          = 002H
_PF_US          = 004H
_PF_RSVD        = 008H
_PF_ID          = 010H

_PAT_PA0        = 000H
_PAT_PA1        = 008H
_PAT_PA2        = 010H
_PAT_PA3        = 018H
_PAT_PA4        = 020H
_PAT_PA5        = 028H
_PAT_PA6        = 030H
_PAT_PA7        = 038H
_PAT_UC         = 0H
_PAT_WC         = 1H
_PAT_WT         = 4H
_PAT_WP         = 5H
_PAT_WB         = 6H
_PAT_UCM        = 7H
_PAT_MASK       = 111B
_IA32_CR_PAT    = 277H

_MTRR_CAP           = 0FEH
_MTRR_CAP_FIX       = (1H shl 8H)
_MTRR_CAP_WC        = (1H shl 00AH)
_MTRR_CAP_SMRR      = (1H shl 00BH)
_MTRR_DEF_TYPE      = 2FFH
_MTRR_DEF_TYPE_FE   = (1H shl 00AH)
_MTRR_DEF_TYPE_E    = (1H shl 00BH)
_MTRR_TYPE_UC       = 0H
_MTRR_TYPE_WC       = 1H
_MTRR_TYPE_WT       = 4H
_MTRR_TYPE_WP       = 5H
_MTRR_TYPE_WB       = 6H
_MTRR_PHYS_MASK_V   = (1H shl 00BH)
_MTRR_FIX_64K_00000 = 250H
_MTRR_FIX_16K_80000 = 258H
_MTRR_FIX_16K_A0000 = 259H
_MTRR_FIX_4K_C0000  = 268H
_MTRR_FIX_4K_C8000  = 269H
_MTRR_FIX_4K_D0000  = 26AH
_MTRR_FIX_4K_D8000  = 26BH
_MTRR_FIX_4K_E0000  = 26CH
_MTRR_FIX_4K_E8000  = 26DH
_MTRR_FIX_4K_F0000  = 26EH
_MTRR_FIX_4K_F8000  = 26FH

_EFER           = 0C0000080H
_EFER_SCE       = (1H shl 0H)
_EFER_LME       = (1H shl 8H)
_EFER_LMA       = (1H shl 00AH)
_EFER_NXE       = (1H shl 00BH)
_EFER_SVME      = (1H shl 00CH)
_EFER_FFXSR     = (1H shl 00EH)

_REP                = 0F3H
_REPNZ              = 0F2H
_CS                 = 02EH
_DS                 = 03EH
_ES                 = 026H
_SS                 = 036H
_FS                 = 064H
_GS                 = 065H
_LOCK               = 0F0H
_OPERAND_SIZE       = 066H
_ADDRESS_SIZE       = 067H
_BRANCH_NOT_TAKEN   = _CS
_BRANCH_TAKEN       = _DS

_PUSHF      = 09CH
_POPF       = 09DH
_INT        = 0CDH
_IRET       = 0CFH
_CLI        = 0FAH
_STI        = 0FBH
_HLT        = 0F4H

_PUSHA_EDI  = 000H
_PUSHA_ESI  = 004H
_PUSHA_EBP  = 008H
_PUSHA_ESP  = 00CH
_PUSHA_EBX  = 010H
_PUSHA_EDX  = 014H
_PUSHA_ECX  = 018H
_PUSHA_EAX  = 01CH
_PUSHA_ALL  = 020H

_IRET_EIP   = 000H
_IRET_CS    = 004H
_IRET_FLAGS = 008H
_IRET_ESP   = 00CH
_IRET_SS    = 010H

_EFLAGS         = (_EFLAGS_IF or _EFLAGS_RSVD)
_EFLAGS_CF      = (1H shl 0H)
_EFLAGS_RSVD    = (1H shl 1H)
_EFLAGS_PF      = (1H shl 2H)
_EFLAGS_AF      = (1H shl 4H)
_EFLAGS_ZF      = (1H shl 6H)
_EFLAGS_SF      = (1H shl 7H)
_EFLAGS_TF      = (1H shl 8H)
_EFLAGS_IF      = (1H shl 9H)
_EFLAGS_DF      = (1H shl 00AH)
_EFLAGS_OF      = (1H shl 00BH)
_EFLAGS_IOPL    = 00CH
_EFLAGS_NT      = (1H shl 00EH)
_EFLAGS_RF      = (1H shl 010H)
_EFLAGS_VM      = (1H shl 011H)
_EFLAGS_AC      = (1H shl 012H)
_EFLAGS_VIF     = (1H shl 013H)
_EFLAGS_VIP     = (1H shl 014H)
_EFLAGS_CPUID   = (1H shl 015H)

_CPUID_EDX_FPU      = (1H shl 0H)
_CPUID_EDX_VME      = (1H shl 1H)
_CPUID_EDX_DE       = (1H shl 2H)
_CPUID_EDX_PSE      = (1H shl 3H)
_CPUID_EDX_MSR      = (1H shl 5H)
_CPUID_EDX_PAE      = (1H shl 6H)
_CPUID_EDX_APIC     = (1H shl 9H)
_CPUID_EDX_SEP      = (1H shl 00BH)
_CPUID_EDX_MTRR     = (1H shr 00CH)
_CPUID_EDX_PGE      = (1H shl 00DH)
_CPUID_EDX_PAT      = (1H shl 010H)
_CPUID_EDX_PSE36    = (1H shl 011H)
_CPUID_EDX_NX       = (1H shl 014H)
_CPUID_EDX_MMX      = (1H shl 017H)
_CPUID_EDX_FXSR     = (1H shl 018H)
_CPUID_EDX_SSE      = (1H shl 019H)
_CPUID_ECX_POPCNT   = (1H shl 017H)

_SYSENTER_CS_MSR    = 174H
_SYSENTER_ESP_MSR   = 175H
_SYSENTER_EIP_MSR   = 176H

_ROOT_UID       = 0H
_GUEST_UID      = 1H
_SCHEDULER_PID  = 0H
_INIT_PID       = 1H

define _last_table
macro page_table _name*, _extension:0H
{
    local _target, _pae, _limit
    _target = 0H
    _pae = (_extension)
    if (_pae)
        _limit = _PAE_TABLE_ENTRY_COUNT
    else
        _limit = _TABLE_ENTRY_COUNT
    end if
    
    macro _page_table_write _value*
    \{
        if (_pae)
            dq (_value)
        else
            dd (_value)
        end if
    \}

    macro _page_table_update _skip
    \{
        local _many
        match _, _skip
        \\{
            _many = (_skip)
            if (_many < 0H)
                _many = (_limit + _many)
            end if
            assert ((_many) < _limit)
            repeat ((_many) - (_target))
                _page_table_write _PE_NULL
            end repeat
            _target = (_many)
        \\}
        assert ((_target) < _limit)
        _target = ((_target) + 1H)
    \}

    macro PT_null _skip
    \{
        _page_table_update _skip
        _page_table_write _PE_NULL
    \}
    
    macro PT_pe _address*, _flags*, _skip
    \{
        _page_table_update _skip
        assert (((_flags) >= 0H) & ((_flags and (not _PAE_XD)) <= 1FFH))
        assert (~((_address) and (_PAGE_FRAME_SIZE - 1H)))
        _page_table_write ((_address) or (_flags))
    \}

    __transform_struc PT_null, PT_pe

    align (_PAGE_FRAME_SIZE)
    match _, _last_table \{ assert 0H \}
    define _last_table _name
    _name:
}

_DE_PRESENT = 080H
rept 4H i:0H
{
    _DPL#i = ((i) shl 5H)
    _RPL#i = (i)
}
_DE_DESCRIPTOR = 010H
_DE_EXECUTABLE = 8H
_DE_CONFORMING = 4H
_DE_EXPAND_DOWN = 4H
_DE_READABLE = 2H
_DE_WRITABLE = 2H
_DE_ACCESS = 1H

_TSS_BUSY = 2H
_TI = 4H

_286_TSS = 1H
_286_LDT = 2H
_286_CALL_GATE = 4H
_286_TASK_GATE = 5H
_286_INTERRUPT_GATE = 6H
_286_TRAP_GATE = 7H

_386_TSS = 9H
_386_CALL_GATE = 00CH
_386_INTERRUPT_GATE = 00EH
_386_TRAP_GATE = 00FH

_DE_L = (2H shl 4H)
_DE_D = (4H shl 4H)
_DE_B = (4H shl 4H)
_DE_G = (8H shl 4H)

struct TSS_16 _link*, _sp0*, _ss0*, _sp1*, _ss1*, _sp2*, _ss2*, _ip*, _flag*, _ax*, _cx*, _dx*, _bx*, _sp*, _bp*, _si*, _di*, _es*, _cs*, _ss*, _ds*, _ldt*
    .link:  dw _link
    .sp0:   dw _ss0
    .ss0:   dw _sp0
    .sp1:   dw _sp1
    .ss1:   dw _ss1
    .sp2:   dw _sp2
    .ss2:   dw _ss2
    .ip:    dw _ip
    .flag:  dw _flag
    .ax:    dw _ax
    .cx:    dw _cx
    .dx:    dw _dx
    .bx:    dw _bx
    .sp:    dw _sp
    .bp:    dw _bp
    .si:    dw _si
    .di:    dw _di
    .es:    dw _es
    .cs:    dw _cs
    .ds:    dw _ds
    .ss:    dw _ss
    .ldt:   dw _ldt
ends

struct TSS_32 _link*, _esp0*, _ss0*, _esp1*, _ss1*, _esp2*, _ss2*, _cr3*, _eip*, _eflag*, _eax*, _ecx*, _edx*, _ebx*,\
        _esp*, _ebp*, _esi*, _edi*, _es*, _cs*, _ss*, _ds*, _fs*, _gs*, _ldt*, _trap*, _iomap*
    .link:  dw _link
            dw 0H
    .esp0:  dd _esp0
    .ss0:   dw _ss0
            dw 0H
    .esp1:  dd _esp1
    .ss1:   dw _ss1
            dw 0H
    .esp2:  dd _esp2
    .ss2:   dw _ss2
            dw 0H
    .cr3:   dd _cr3
    .eip:   dd _eip
    .eflag: dd _eflag
    .eax:   dd _eax
    .ecx:   dd _ecx
    .edx:   dd _edx
    .ebx:   dd _ebx
    .esp:   dd _esp
    .ebp:   dd _ebp
    .esi:   dd _esi
    .edi:   dd _edi
    .es:    dw _es
            dw 0H
    .cs:    dw _cs
            dw 0H
    .ss:    dw _ss
            dw 0H
    .ds:    dw _ds
            dw 0H
    .fs:    dw _fs
            dw 0H
    .gs:    dw _gs
            dw 0H
    .ldt:   dw _ldt
            dw 0H
    .trap:  dw _trap
    .iomap: dw _iomap
ends

;__transform_struc TSS_16, TSS_32

macro descriptor_table _name*, _local:0H
{
    local _selector
    _selector = 0H

    macro _descriptor_table_retreive _target*
    \{
        local _mask
        _mask = 0H
        _target:
        if (_local)
            _mask = _TI
        end if
        _target\#.selector = (((_selector) * 8H) or _mask)
        _selector = ((_selector) + 1H)
    \}

    struc DT_null
    \{
        _descriptor_table_retreive .
        dq 0H
    \}

    struc DT_dte _flag*, _access*, _offset*, _limit*
    \{
        _descriptor_table_retreive .
        assert (((_limit) >= 0H) & ((_limit) <= 00FFFFFH))
        assert (((_offset) >= 0H) & ((_offset) <= 0FFFFFFFFH))
        .limit_1: dw ((_limit) and 0FFFFH)
        .offset_1: dw ((_offset) and 0FFFFH)
        .offset_2: db (((_offset) shr 010H) and 0FFH)
        .access: db ((_access) or _DE_DESCRIPTOR)
        .limit_2:
        .flag: db ((_flag) or ((_limit) shr 010H))
        .offset_3: db ((_offset) shr 018H)
    \}

    struc DT_gte _access*, _wdcnt*, _select*, _offset*
    \{
        _descriptor_table_retreive .
        assert (((_offset) >= 0H) & ((_offset) <= 0FFFFFFFFH))
        assert (((_select) >= 0H) & ((_select) <= 0FFFFH))
        assert (((_wdcnt) >= 0H) & ((_wdcnt) <= 01FH))
        .offset_1: dw ((_offset) and 0FFFFH)
        .select: dw (_select)
        .wdcnt: db (_wdcnt)
        .access: db ((_access) and (not _DE_DESCRIPTOR))
        .offset_2: dw ((_offset) shr 010H)
    \}

    struc DT_ste _access*, _offset*, _limit*
    \{
        _descriptor_table_retreive .
        assert (((_limit) >= 0H) & ((_limit) <= 00FFFFFH))
        assert (((_offset) >= 0H) & ((_offset) <= 0FFFFFFFFH))
        .limit_1: dw ((_limit) and 0FFFFH)
        .offset_1: dw ((_offset) and 0FFFFH)
        .offset_2: db (((_offset) shr 010H) and 0FFH)
        .access: db ((_access) and (not _DE_DESCRIPTOR))
        .limit_2: db ((_limit) shr 010H)
        .offset_3: db ((_offset) shr 018H)
    \}

;    __transform_struc DT_null, DT_dte, DT_gte, DT_ste

    align (8H)
;    psegment _name
    _name:
}

_context = ($)
define _restore
macro psegment _name*, _mode:use32
{
    local _base
    _base = ($)
    match,_restore \{ _context = (_base) \}
    match _, _restore \{ _context = (_context + (_base)) \}
    define _restore _base,_name
    label _name#.start at 0H
    label _name at _context
    org 0H
    _mode
}

macro _segsize _target*, _size*
{
    _target = ((_size) - 1H)
    assert ((_target) >= 0H)
}

macro _segresv _name*, _origin*, _size*
{
    label _name at (_origin)
    label _name#.start at 0H
    _segsize _name#.size, (_size)
}

macro end _continue*
{
    local _missed
    define _missed
    match =psegment, _continue \{ define _missed psegment \}
    match =descriptor_table, _continue \{ define _missed descriptor_table \}
    match =page_table, _continue \{ define _missed page_table \}
    match _, _missed
    \{
        match =descriptor_table, _
        \\{
            restruc DT_null, DT_dte, DT_gte, DT_ste
            purge DT_null, DT_dte, DT_gte, DT_ste, _descriptor_table_retreive
        \\}
        match =page_table, _
        \\{
            if (($ = _last_table) | ($ and (_PAGE_FRAME_SIZE - 1H)))
                PT_null -1H
            end if
            restore _last_table
            restruc PT_null, PT_pe
            purge PT_null, PT_pe, _page_table_update, _page_table_write
        \\}
        match _base=,_name, _restore
        \\{
            _segsize _name\\#.size, ($)
            _context = (_context - (_base))
            org (_base + ($))
        \\}
        restore _restore
    \}
    match,_missed \{ end _continue \}
}

macro enum [item*]
{
 common
    local _start, _bmask, _first, _item, _number
    _start = 0H
    _bmask = 0H
    _first = 1H
 forward
    define _item item
    match =& _target, _item
    \{
        assert (_first)
        define _item _target
        _bmask = 1H
    \}
    match _target =: _attribute, _item
    \{
        define _item _target
        define _number
        match =&, _attribute
        \\{
            assert (~(_first))
            _start = ((_start) - 1H)
            define _number _
        \\}
        match,_number
        \\{
            assert ((_start) <= (_attribute))
            _start = _attribute
        \\}
    \}
    match _, _item
    \{
        assert (~(definite (_)))
        if (_bmask)
            _ = (1H shl (_start))
        else
            _ = (_start)
        end if
    \}
    _start = ((_start) + 1H)
    _first = 0H
}

macro _round_up _register*, _power_two*
{
    assert ((bsf (_power_two)) = (bsr (_power_two)))
    add _register, ((_power_two) - 1H)
    shr _register, (bsf (_power_two))
}

macro _align_up _register*, _power_two*
{
    assert ((bsf (_power_two)) = (bsr (_power_two)))
    add _register, ((_power_two) - 1H)
    and _register, (not ((_power_two) - 1H))
}

macro _real_segment _result*, _pointer*
{
    match _segment:_offset, _pointer
    \{
        shl _segment, 4H
        lea _result, [_segment+_offset]
    \}
}

macro _salc
{
    lahf
    sbb al, al
    sahf
}

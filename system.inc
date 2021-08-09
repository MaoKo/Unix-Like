
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

_MAX_REAL_ADDRESS = ((0FFFFH shl 4H) + 0FFFFH)
_CMOS_DISABLE_NMI = (1H shl 7H)
_CMOS_SELECT = 070H
_CMOS_PORT = 071H
_RESET_CODE_BYTE = 00FH
_BIOS_JUMP_EOI = 5H
_BIOS_JUMP = 00AH ; without EOI
_WARN_RESET_VECTOR = ((040H shl 4H) + 067H)
_COPROCESSOR_ERROR = 0F0H

_CR0_PE     = (1H shl 0H)
_CR0_MP     = (1H shl 1H)
_CR0_EM     = (1H shl 2H)
_CR0_TS     = (1H shl 3H)
_CR0_ET     = (1H shl 4H)
_CR0_NE     = (1H shl 5H)
_CR0_WP     = (1H shl 010H)
_CR0_AM     = (1H shl 012H)
_CR0_NW     = (1H shl 01DH)
_CR0_CD     = (1H shl 01EH)
_CR0_PG     = (1H shl 01FH)

_CR4_VME        = (1H shl 0H)
_CR4_PVI        = (1H shl 1H)
_CR4_TSD        = (1H shl 2H)
_CR4_DE         = (1H shl 3H)
_CR4_PSE        = (1H shl 4H)
_CR4_PAE        = (1H shl 5H)
_CR4_MCE        = (1H shl 6H)
_CR4_PGE        = (1H shl 7H)
_CR4_PCE        = (1H shl 8H)
_CR4_OSFXSR     = (1H shl 9H)
_CR4_OSXMMEXCPT = (1H shl 00AH)
_CR4_UMIP       = (1H shl 00BH)
_CR4_LA57       = (1H shl 00CH)
_CR4_VMXE       = (1H shl 00DH)
_CR4_SMXE       = (1H shl 00EH)
_CR4_FSGSBASE   = (1H shl 010H)
_CR4_PCIDE      = (1H shl 011H)
_CR4_OSXSAVE    = (1H shl 012H)
_CR4_LK         = (1H shl 013H)
_CR4_SMEP       = (1H shl 014H)
_CR4_SMAP       = (1H shl 015H)
_CR4_PKE        = (1H shl 016H)
_CR4_CET        = (1H shl 017H)
_CR4_PKS        = (1H shl 018H)

_XCR0           = 0H
_IA32_XSS       = 00DA0H
_XCR0_x87       = (1H shl 0H)
_XCR0_SSE       = (1H shl 1H)
_XCR0_AVX       = (1H shl 2H)
_XCR0_MPX       = (1H shl 3H)
_XCR0_AVX_512   = (1H shl 5H)
_XCR0_PKRU      = (1H shl 9H)
_XSS_PT         = (1H shl 8H)
_XSS_CET_UST    = (1H shl 00BH)
_XSS_CET_SST    = (1H shl 00CH)
_XSS_HDC        = (1H shl 00DH)
_XSS_HWP        = (1H shl 010H)

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
_MTRR_CAP_VCNT_MASK = 0FFH
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
_MTRR_PHYS_BASE_0   = 200H
_MTRR_PHYS_MASK_0   = 201H
_MTRR_PHYS_BASE_1   = 202H
_MTRR_PHYS_MASK_1   = 203H
_MTRR_PHYS_BASE_2   = 204H
_MTRR_PHYS_MASK_2   = 205H
_MTRR_PHYS_BASE_3   = 206H
_MTRR_PHYS_MASK_3   = 207H
_MTRR_PHYS_BASE_4   = 208H
_MTRR_PHYS_MASK_4   = 209H
_MTRR_PHYS_BASE_5   = 20AH
_MTRR_PHYS_MASK_5   = 20BH
_MTRR_PHYS_BASE_6   = 20CH
_MTRR_PHYS_MASK_6   = 20DH
_MTRR_PHYS_BASE_7   = 20EH
_MTRR_PHYS_MASK_7   = 20FH
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
_MTRR_PENTIUM       = 8H
_SMRR_PHYSBASE      = 1F2H
_SMRR_PHYSMASK      = 1F3H

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
_RDMSR      = 0320FH
_WRMSR      = 0300FH

_PUSHA_EDI      = 000H
_PUSHA_ESI      = 004H
_PUSHA_EBP      = 008H
_PUSHA_ESP      = 00CH
_PUSHA_EBX      = 010H
_PUSHA_EDX      = 014H
_PUSHA_ECX      = 018H
_PUSHA_EAX      = 01CH
_PUSHA_TOTAL    = 020H

_EXCEPTION_DIVIDE_BY_ZERO               = 0H
_EXCEPTION_DEBUG                        = 1H
_EXCEPTION_NMI                          = 2H
_EXCEPTION_BREAKPOINT                   = 3H
_EXCEPTION_OVERFLOW                     = 4H
_EXCEPTION_ARRAY_BOUND_CHECK            = 5H
_EXCEPTION_INVALID_OPCODE               = 6H
_EXCEPTION_DEVICE_NOT_AVAILABLE         = 7H
_EXCEPTION_DOUBLE_FAULT                 = 8H
_EXCEPTION_COPROCESSOR_SEGMENT_OVERRUN  = 9H
_EXCEPTION_INVALID_TSS                  = 00AH
_EXCEPTION_SEGMENT_NOT_PRESENT          = 00BH
_EXCEPTION_STACK                        = 00CH
_EXCEPTION_GENERAL_PROTECTION           = 00DH
_EXCEPTION_PAGE_FAULT                   = 00EH
_EXCEPTION_FPU                          = 010H
_EXCEPTION_ALIGNEMENT_CHECK             = 011H
_EXCEPTION_MACHINE_CHECK                = 012H
_EXCEPTION_SMID                         = 013H
_EXCEPTION_VIRTUALIZATION               = 014H

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

_CPUID_LEAF_PROCESSOR_INFO      = 1H
_CPUID_LEAF_EXTEND_FEATURE      = 7H
_CPUID_SUBLEAF_EXTEND_FEATURE   = 0H
_CPUID_LEAF_EXTEND_STATE        = 00DH
_CPUID_SUBLEAF_EXTEND_STATE     = 1H
_CPUID_LEAF_EXTEND_INFO         = 080000001H
_CPUID_LEAF_VIRTPHYSIZE         = 080000008H

_CPUID_EAX_XSAVES       = (1H shl 3H)
_CPUID_EBX_LINSZMSK     = (0FFH shl _CPUID_EBX_LINSZSHT)
_CPUID_EBX_LINSZSHT     = 8H
_CPUID_EBX_LPROCMSK     = (0FFH shl _CPUID_EBX_LPROCSHT)
_CPUID_EBX_LPROCSHT     = 010H
_CPUID_EBX_FSGSBASE     = (1H shl 0H)
_CPUID_EBX_BMI1         = (1H shl 3H)
_CPUID_EBX_SMEP         = (1H shl 7H)
_CPUID_EBX_BMI2         = (1H shl 8H)
_CPUID_EBX_RDSEED       = (1H shl 012H)
_CPUID_EBX_SMAP         = (1H shl 014H)
_CPUID_EBX_SHA          = (1H shl 01DH)
_CPUID_EDX_FPU          = (1H shl 0H)
_CPUID_EDX_VME          = (1H shl 1H)
_CPUID_EDX_DE           = (1H shl 2H)
_CPUID_EDX_PSE          = (1H shl 3H)
_CPUID_EDX_MSR          = (1H shl 5H)
_CPUID_EDX_PAE          = (1H shl 6H)
_CPUID_EDX_MCE          = (1H shl 7H)
_CPUID_EDX_APIC         = (1H shl 9H)
_CPUID_EDX_SEP          = (1H shl 00BH)
_CPUID_EDX_MTRR         = (1H shl 00CH)
_CPUID_EDX_PGE          = (1H shl 00DH)
_CPUID_EDX_MCA          = (1H shl 00EH)
_CPUID_EDX_CMOV         = (1H shl 00FH)
_CPUID_EDX_PAT          = (1H shl 010H)
_CPUID_EDX_PSE36        = (1H shl 011H)
_CPUID_EDX_CLFLUSH      = (1H shl 013H)
_CPUID_EDX_NX           = (1H shl 014H)
_CPUID_EDX_MMX          = (1H shl 017H)
_CPUID_EDX_FXSR         = (1H shl 018H)
_CPUID_EDX_SSE          = (1H shl 019H)
_CPUID_EDX_SSE2         = (1H shl 01AH)
_CPUID_EDX_HTT          = (1H shl 01CH)
_CPUID_ECX_SSE3         = (1H shl 0H)
_CPUID_ECX_PCLMULQDQ    = (1H shl 1H)
_CPUID_ECX_UMIP         = (1H shl 2H)
_CPUID_ECX_PKU          = (1H shl 3H)
_CPUID_ECX_VMX          = (1H shl 5H)
_CPUID_ECX_SSSE3        = (1H shl 9H)
_CPUID_ECX_PCID         = (1H shl 011H)
_CPUID_ECX_SSE41        = (1H shl 013H)
_CPUID_ECX_SSE42        = (1H shl 014H)
_CPUID_ECX_X2APIC       = (1H shl 015H)
_CPUID_ECX_POPCNT       = (1H shl 017H)
_CPUID_ECX_AES          = (1H shl 019H)
_CPUID_ECX_XSAVE        = (1H shl 01AH)
_CPUID_ECX_OSXSAVE      = (1H shl 01BH)
_CPUID_ECX_AVX          = (1H shl 01CH)
_CPUID_ECX_PKS          = (1H shl 01FH)

_SYSENTER_CS_MSR    = 174H
_SYSENTER_ESP_MSR   = 175H
_SYSENTER_EIP_MSR   = 176H

_POWER_ON_RESTART_ADDRESS           = 0FFFFFFF0H
_SM_BASE                            = 30000H
_BOCHS_SM_BASE                      = 00A0000H
_SM_ENTRY_POINT                     = 08000H
_SM_REVISION_ID_MASK                = 0FFFFH
_SM_REVISION_IO_RESTART             = (1H shl 010H)
_SM_REVISION_BASE_RELOCATION        = (1H shl 011H)
_SM_AUTO_HALT                       = 1H

_SM_IA32_STATE_SAVE_SMBASE          = 07EF8H
_SM_IA32_STATE_SAVE_REVISION        = 07EFCH
_SM_IA32_STATE_SAVE_IO_RESTART      = 07F00H
_SM_IA32_STATE_SAVE_HALT_RESTART    = 07F02H
;_SM_STATE_SAVE_
_SM_IA32_STATE_SAVE_ES              = 07FA8H
_SM_IA32_STATE_SAVE_CS              = 07FACH
_SM_IA32_STATE_SAVE_SS              = 07FB0H
_SM_IA32_STATE_SAVE_DS              = 07FB4H
_SM_IA32_STATE_SAVE_FS              = 07FB8H
_SM_IA32_STATE_SAVE_GS              = 07FBCH
_SM_IA32_STATE_SAVE_TR              = 07FC4H
_SM_IA32_STATE_SAVE_DR7             = 07FC8H
_SM_IA32_STATE_SAVE_DR6             = 07FCCH
_SM_IA32_STATE_SAVE_EAX             = 07FD0H
_SM_IA32_STATE_SAVE_ECX             = 07FD4H
_SM_IA32_STATE_SAVE_EDX             = 07FD8H
_SM_IA32_STATE_SAVE_EBX             = 07FDCH
_SM_IA32_STATE_SAVE_ESP             = 07FE0H
_SM_IA32_STATE_SAVE_EBP             = 07FE4H
_SM_IA32_STATE_SAVE_ESI             = 07FE8H
_SM_IA32_STATE_SAVE_EDI             = 07FECH
_SM_IA32_STATE_SAVE_EIP             = 07FF0H
_SM_IA32_STATE_SAVE_EFLAGS          = 07FF4H
_SM_IA32_STATE_SAVE_CR3             = 07FF8H
_SM_IA32_STATE_SAVE_CR0             = 07FFCH

_SM_IA32E_STATE_SAVE_CR0            = 07FF8H

_BOCHS_SMI_COMMAND_IO       = 0B2H

_MCG_CAP        = 179H
_MCG_STATUS     = 17AH
_MCG_CTL        = 17BH
_MCG_MISC       = 18AH
_MCG_CAP_COUNT_MASK = 0FFH
_MCG_CAP_MCG_CTL_P  = (1H shl 8H)
_MCG_CAP_MCG_EXT_P  = (1H shl 9H)
_MCG_CAP_MCG_CMCI_P = (1H shl 00AH)
_MCG_CAP_MCG_TES_P  = (1H shl 00BH)
_MCG_STATUS_RIPV    = (1H shl 0H)
_MCG_STATUS_EIPV    = (1H shl 1H)
_MCG_STATUS_MCIP    = (1H shl 2H)

_MCG_MISC_DS        = (1H shl 0H)

_FS_BASE        = 0C0000100H
_GS_BASE        = 0C0000101H
_KERNEL_GS_BASE = 0C0000102H

_TSC    = 010H ; executing rdtsc(p) is the same as reading this MSR

_PERF_CTR_0 = 0C1H
_PERF_CTR_1 = 0C2H

_IA32_VMX_BASIC         = 480H
_VMCS_REVISION_ID       = 0H
_VMCS_ABORT_INDICATOR   = 4H

_DEFAULT_LOCAL_APIC     = 0FEE00000H
_DEFAULT_IO_APIC        = 0FEC00000H

_APIC_DELIVERY_FIXED    = (000B shl 8H)
_APIC_DELIVERY_SMI      = (010B shl 8H)
_APIC_DELIVERY_NMI      = (100B shl 8H)
_APIC_DELIVERY_INIT     = (101B shl 8H)
_APIC_DELIVERY_EXTINT   = (111B shl 8H)
_APIC_LEVEL_TRIGGER     = (1H shl 00FH)
_APIC_POLARITY_LOW      = (1H shl 00DH)

; LOCAL APIC
_IA32_APIC_BASE     = 01BH
_APIC_BASE_BSP      = (1H shl 8H)
_APIC_BASE_EXTD     = (1H shl 00AH)
_APIC_BASE_EN       = (1H shl 00BH)
_APIC_BASE_ADDRESS  = (1H shl 00CH)

_LOCAL_APIC_BASE_MSR                = 800H
_LOCAL_APIC_ID_REGISTER             = 020H
;_LOCAL_APIC_ID_REGISTER_MSR     = (_LOCAL_APIC_BASE_MSR + 2H)
_LOCAL_APIC_VERSION_REGISTER        = 030H
_TASK_PRIORITY_REGISTER             = 080H
_ARBITRATION_PRIORITY_REGISTER      = 090H
_PROCESSOR_PRIORITY_REGISTER        = 0A0H
_LOCAL_EOI_REGISTER                 = 0B0H
_REMOTE_READ_REGISTER               = 0C0H
_LOGICAL_DESTINATION_REGISTER       = 0D0H
_DESTINATION_FORMAT_REGISTER        = 0E0H
_SPURIOUS_INTERRUPT_VECTOR_REGISTER = 0F0H
rept 8H i:1H { _IN_SERVICE_REGISTER_#i = (100H + ((i - 1H) shl 4H)) }
rept 8H i:1H { _TRIGGER_MODE_REGISTER_#i = (180H + ((i - 1H) shl 4H)) }
rept 8H i:1H { _INTERRUPT_REQUEST_REGISTER_#i = (200H + ((i - 1H) shl 4H)) }
_ERROR_STATUS_REGISTER              = 280H
_LVT_CMC                            = 2F0H
_INTERRUPT_COMMAND_REGISTER_LOW     = 300H
_INTERRUPT_COMMAND_REGISTER_HIGH    = 310H
_LVT_TIMER                          = 320H
_LVT_THERMAL_SENSOR                 = 330H
_LVT_PERF_COUNTER_OVERFLOW          = 340H
_LVT_LINT0                          = 350H
_LVT_LINT1                          = 360H
_TIMER_INITIAL_COUNT_REGISTER       = 380H
_TIMER_CURRENT_COUNT_REGISTER       = 390H
_TIMER_DIVIDE_CONFIG_REGISTER       = 3E0H

; IO APIC
_INDEX_REGISTER                     = 000H
_DATA_REGISTER                      = 010H
_IRQ_PIN_ASSERTION_REGISTER         = 020H
_IO_EOI_REGISTER                    = 040H
; IO APIC INDEX
_IDENTIFICATION_REGISTER            = 000H
_IO_APIC_VERSION_REGISTER           = 001H
_IO_APIC_VERSION_MASK               = 0FFH
_IO_APIC_VERSION_PRQ                = (1H shl 00FH)
_IO_APIC_VERSION_IRQ_RT_MASK        = 0FFH
_IO_APIC_VERSION_IRQ_RT_SHIFT       = 010H
_REDIRECTION_TABLE_BASE             = 010H

_LVT_LINT_VECTOR_MASK       = 0FFH
_LVT_LINT_DELIVERY_FIXED    = (000B shl 8H)
_LVT_LINT_DELIVERY_SMI      = (010B shl 8H)
_LVT_LINT_DELIVERY_NMI      = (100B shl 8H)
_LVT_LINT_DELIVERY_INIT     = (101B shl 8H)
_LVT_LINT_DELIVERY_EXTINT   = (111B shl 8H)
_LVT_LINT_SEND_PENDING      = (1H shl 00CH)
_LVT_LINT_IDLE              = 0H
_LVT_LINT_ACTIVE_LOW        = (1H shl 00DH)
_LVT_LINT_ACTIVE_HIGH       = 0H
_LVT_LINT_REMOTE_IRR        = (1H shl 00EH)
_LVT_LINT_LEVEL_SENSITIVE   = (1H shl 00FH)
_LVT_LINT_EDGE_TRIGGERED    = 0H
_LVT_LINT_MASKED            = (1H shl 010H)
_LVT_LINT_UNMASKED          = 0H

_LVT_TIMER_DIVIDE_2     = 00000B
_LVT_TIMER_DIVIDE_4     = 00001B
_LVT_TIMER_DIVIDE_8     = 00010B
_LVT_TIMER_DIVIDE_16    = 00011B
_LVT_TIMER_DIVIDE_32    = 01000B
_LVT_TIMER_DIVIDE_64    = 01001B
_LVT_TIMER_DIVIDE_128   = 01010B
_LVT_TIMER_DIVIDE_1     = 01011B

_ICR_XAPIC_DESTINATION_SHIFT    = 038H
_ICR_X2APIC_DESTINATION_SHIFT   = 020H
_ICR_NO_SHORTHAND               = (000B shl 012H)
_ICR_SELF                       = (001B shl 012H)
_ICR_ALL_INCLUDING_SELF         = (010B shl 012H)
_ICR_ALL_EXCLUDING_SELF         = (011B shl 012H)
_ICR_LEVEL_ASSERT               = (1H shl 00EH)

_APIC_VERSION_MASK              = 0FFH
_APIC_VERSION_LVT_SHIFT         = 010H
_APIC_VERSION_LVT_MASK          = 0FFH
_APIC_VERSION_DEOI              = (1H shl 018H)

_SPURIOUS_VECTOR_MASK           = 0FFH
_SPURIOUS_APIC_ENABLE           = (1H shl 8H)
_SPURIOUS_EOI_BROADCAST_DISABLE = (1H shl 00CH)

rept 010H i:0H
{
    _AD_#i = (1H shl ((i) * 2H))
    _WD_#i = (1H shl (((i) * 2H) + 1H))
}
_IA32_PKRS = 6E1H

_IA32_MISC_ENABLE               = 1A0H
_MISC_FAST_STRING_ENABLE        = (1H shl 0H)
_MISC_ENABLE_FOPCODE            = (1H shl 2H) 
_MISC_ENABLE_THERMAL_MONITOR    = (1H shl 3H)
_MISC_SPLIT_LOCK_DISABLE        = (1H shl 4H)
_MISC_FERR_INTERRUPT_REPORT     = (1H shl 00AH)
_MISC_ENABLE_XD_DISABLE         = (1H shl 022H)

_SP_FP_SGNSHT       = 01FH
_SP_FP_EXPMSK       = (((1H shl (_SP_FP_SGNSHT - _SP_FP_EXPSHT)) - 1H) shl _SP_FP_EXPSHT)
_SP_FP_EXPSHT       = 017H
_SP_FP_FRCMSK       = (((1H shl _SP_FP_EXPSHT) - 1H) shl _SP_FP_FRCSHT)
_SP_FP_FRCSHT       = 0H
_SP_FP_BIAS         = 0H

_DP_FP_SNGSHT       = 03FH
_DP_FP_EXPMSK       = (((1H shl (_DP_FP_SNGSHT - _DP_FP_EXPSHT)) - 1H) shl _DP_FP_EXPSHT)
_DP_FP_EXPSHT       = 034H
_DP_FP_FRCMSK       = (((1H shl _DP_FP_EXPSHT) - 1H) shl _DP_FP_FRCSHT)
_DP_FP_FRCSHT       = 0H
_DP_FP_BIAS         = 0H

_DEP_FP_SNGSHT      = 04FH
_DEP_FP_EXPMSK_HIGH = (((1H shl ((_DEP_FP_SNGSHT - 1H) - _DEP_FP_EXPSHT + 1H)) - 1H) shl (_DEP_FP_EXPSHT - 040H))
_DEP_FP_EXPMSK_LOW  = 0H
_DEP_FP_EXPSHT      = 040H
_DEP_FP_INTSHT      = 03FH
_DEP_FP_FRCMSK      = (((1H shl _DEP_FP_INTSHT) - 1H) shl _DEP_FP_FRCSHT)
_DEP_FP_FRCSHT      = 0H

_SP_FP_POSITIVE_ZERO        = 0H
_SP_FP_NEGATIVE_ZERO        = (1B shl _SP_FP_SGNSHT)
_SP_FP_POSITIVE_INFINITY    = (_SP_FP_EXPMSK)
_SP_FP_NEGATIVE_INFINITY    = (_SP_FP_NEGATIVE_ZERO or _SP_FP_POSITIVE_INFINITY)
_SP_FP_POSITIVE_QNAN        = (_SP_FP_POSITIVE_INFINITY or (1H shl (_SP_FP_EXPSHT - 1H)) or 1H)
_SP_FP_NEGATIVE_QNAN        = (_SP_FP_NEGATIVE_INFINITY or _SP_FP_POSITIVE_QNAN)
_SP_FP_POSITIVE_SNAN        = (_SP_FP_POSITIVE_INFINITY or 1H)
_SP_FP_NEGATIVE_SNAN        = (_SP_FP_NEGATIVE_INFINITY or _SP_FP_POSITIVE_SNAN)
_SP_FP_POSITIVE_DENORMAL    = 0H
_SP_FP_NEGATIVE_DENORMAL    = 0H

_DP_FP_POSITIVE_ZERO        = 0H
_DP_FP_NEGATIVE_ZERO        = (1B shl _DP_FP_SNGSHT)
_DP_FP_POSITIVE_INFINITY    = (_DP_FP_EXPMSK)
_DP_FP_NEGATIVE_INFINITY    = (_DP_FP_NEGATIVE_ZERO or _DP_FP_POSITIVE_INFINITY)
_DP_FP_POSITIVE_QNAN        = (_DP_FP_POSITIVE_INFINITY or (1H shl (_DP_FP_EXPSHT - 1H)) or 1H)
_DP_FP_NEGATIVE_QNAN        = (_DP_FP_NEGATIVE_INFINITY or _DP_FP_POSITIVE_QNAN)
_DP_FP_POSITIVE_SNAN        = (_DP_FP_POSITIVE_INFINITY or 1H)
_DP_FP_NEGATIVE_SNAN        = (_DP_FP_NEGATIVE_INFINITY or _DP_FP_POSITIVE_SNAN)

_DEP_FP_POSITIVE_ZERO_HIGH      = 0H
_DEP_FP_POSITIVE_ZERO_LOW       = 0H
_DEP_FP_NEGATIVE_ZERO_HIGH      = (1H shl (_DEP_FP_SNGSHT - 040H))
_DEP_FP_NEGATIVE_ZERO_LOW       = _DEP_FP_POSITIVE_ZERO_LOW
_DEP_FP_POSITIVE_INFINITY_HIGH  = _DEP_FP_EXPMSK_HIGH
_DEP_FP_POSITIVE_INFINITY_LOW   = _DEP_FP_EXPMSK_LOW
_DEP_FP_NEGATIVE_INFINITY_HIGH  = (_DEP_FP_NEGATIVE_ZERO_HIGH or _DEP_FP_POSITIVE_INFINITY_HIGH)
_DEP_FP_NEGATIVE_INFINITY_LOW   = 0H

_DEP_FP_POSITIVE_QNAN_HIGH      = _DEP_FP_POSITIVE_INFINITY_HIGH
_DEP_FP_POSITIVE_QNAN_LOW       = (_DEP_FP_POSITIVE_INFINITY_LOW or (1H shl (_DEP_FP_INTSHT - 1H)) or 1H)

;_DEP_FP_NEGATIVE_SNAN_HIGH      = (_DEP_FP_POSITIVE_SNAN_HIGH)


_FCW_IM             = (1H shl 0H)
_FCW_DM             = (1H shl 1H)
_FCW_ZM             = (1H shl 2H)
_FCW_OM             = (1H shl 3H)
_FCW_UM             = (1H shl 4H)
_FCW_PM             = (1H shl 5H)
_FCW_PC_SP          = (000B shl 8H)
_FCW_PC_DP          = (010B shl 8H)
_FCW_PC_DEP         = (011B shl 8H)
_FCW_RC_NEAREST     = (000B shl 00AH)
_FCW_RC_DOWN        = (001B shl 00AH)
_FCW_RC_UP          = (010B shl 00AH)
_FCW_RC_ZERO        = (011B shl 00AH)
_FCW_IC             = (1H shl 00CH)

_FSW_IE             = (1H shl 0H)
_FSW_DE             = (1H shl 1H)
_FSW_ZE             = (1H shl 2H)
_FSW_OE             = (1H shl 3H)
_FSW_UE             = (1H shl 4H)
_FSW_PE             = (1H shl 5H)
_FSW_SF             = (1H shl 6H)
_FSW_ES             = (1H shl 7H)
_FSW_C0             = (1H shl 8H)
_FSW_C1             = (1H shl 9H)
_FSW_C2             = (1H shl 00AH)
_FSW_TOP            = (1H shl 00BH)
_FSW_C3             = (1H shl 00EH)
_FSW_B              = (1H shl 00FH)

_FTW_VALID          = 000B
_FTW_ZERO           = 001B
_FTW_SPECIAL        = 010B
_FTW_EMPTY          = 011B
rept 8H i:0H        { _FTW_TAG#i = ((i) shl 1H) }

_MXCSR_IE           = (1H shl 0H)
_MXCSR_DE           = (1H shl 1H)
_MXCSR_ZE           = (1H shl 2H)
_MXCSR_OE           = (1H shl 3H)
_MXCSR_UE           = (1H shl 4H)
_MXCSR_PE           = (1H shl 5H)
_MXCSR_DAZ          = (1H shl 6H)
_MXCSR_IM           = (1H shl 7H)
_MXCSR_DM           = (1H shl 8H)
_MXCSR_ZM           = (1H shl 9H)
_MXCSR_OM           = (1H shl 00AH)
_MCXSR_UM           = (1H shl 00BH)
_MXCSR_PM           = (1H shl 00CH)
_MXCSR_RC           = (1H shl 00DH)
_MXCSR_FTZ          = (1H shl 00FH)

_FXSAVE_FCW             = 0H
_FXSAVE_FSW             = 2H
_FXSAVE_FTW             = 4H
_FXSAVE_FOP             = 6H
_FXSAVE_EIP             = 8H
_FXSAVE_CS              = 00CH
_FXSAVE_DATA_POINTER    = 010H
_FXSAVE_DS              = 014H
_FXSAVE_MXCSR           = 018H
_FXSAVE_MXCSR_MASK      = 01CH
_FXSAVE_ST0_MM0         = 020H
_FXSAVE_ST1_MM1         = 030H
_FXSAVE_ST2_MM2         = 040H
_FXSAVE_ST3_MM3         = 050H
_FXSAVE_ST4_MM4         = 060H
_FXSAVE_ST5_MM5         = 070H
_FXSAVE_ST6_MM6         = 080H
_FXSAVE_ST7_MM7         = 090H
_FXSAVE_XMM0            = 0A0H
_FXSAVE_XMM1            = 0B0H
_FXSAVE_XMM2            = 0C0H
_FXSAVE_XMM3            = 0D0H
_FXSAVE_XMM4            = 0E0H
_FXSAVE_XMM5            = 0F0H
_FXSAVE_XMM6            = 100H
_FXSAVE_XMM7            = 110H
_FXSAVE_TOTAL           = 200H

_UMIP_ALLOW     = 0H    

_ROOT_UID       = 0H
_GUEST_UID      = 1H
_SCHEDULER_PID  = 0H
_INIT_PID       = 1H
_PORT_AVAILABLE = 010000H

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

_DE_L = (2H shl 4H) ; long mode bit
_DE_D = (4H shl 4H) ; default bit
_DE_B = (4H shl 4H) ; big bit
_DE_G = (8H shl 4H) ; granularity bit

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

struct DT_null
    dq 0H
ends

struct DT_gte _access*, _wdcnt*, _select*, _offset*
    assert (((_offset) >= 0H) & ((_offset) <= 0FFFFFFFFH))
    assert (((_select) >= 0H) & ((_select) <= 0FFFFH))
    assert (((_wdcnt) >= 0H) & ((_wdcnt) <= 01FH))
    .offset_1:  dw ((_offset) and 0FFFFH)
    .select:    dw (_select)
    .wdcnt:     db (_wdcnt)
    .access:    db ((_access) and (not _DE_DESCRIPTOR))
    .offset_2:  dw ((_offset) shr 010H)
ends

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

struc _bitwise _mask*, _shift*
{
    .#_MASK     = ((_mask) shl .#_SHIFT)
    .#_SHIFT    = (_shift)
}

macro _debugs _list*&
{
    local _address
    irp _address, _list
    \{
        align 010H, 020H
        db "0x"
        _itoa _address
    \}
}


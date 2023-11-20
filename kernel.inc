
; User Memory Map (World view)
; +----------------------+
; |                      | 000000000H (prevent dereference 0H)
; |----------------------|
; |                      |
; |  User Runnable Code  |
; |                      |
; |----------------------| Program break (extend on brk by page unit)
; |                      |
; |                      |
; |                      |
; |                      |
; |                      |
; |                      |
; |                      |
; |      User Space      |
; |                      |
; |                      |
; |                      |
; |                      |
; |                      |
; |                      | 
; |                      |
; |----------------------| Stack expand on page fault
; |      User Stack      |
; |----------------------|
; | User Shell Arguments | IPC for argument
; ////////////////////////
; |                      | 0C0000000H (principally for interrupts/syscall)
; |                      |
; |                      |
; |                      |
; |                      |
; |                      |
; |                      |
; |                      |
; |     Kernel Space     |
; |                      |
; |                      |
; |                      |
; |                      |
; |                      |
; |                      |
; |----------------------|
; |  IO  APIC Registers  |
; |----------------------|
; | Local APIC Registers | Used by Legacy APIC, xAPIC (x2APIC use MSR)
; |----------------------|
; |  VDSO Runnable Code  | Used by sigret syscall and sysenter
; ////////////////////////
; |   Video Framebuffer  | 16Mb to sastify all kind of resolution
; ////////////////////////
; |  Temporary Mappings  | (duplicate PD/PT when address > 020H (only if PAE))
; |``````````````````````| Recursive mapping (used for mmap without changing cr3)
; |``````````````````````| 0FFC00000H (without PAE)
; |``````````````````````| 0FF600000H (with    PAE)
; |  Recursive Mappings  |
; +----------------------+

; Kernel Memory Map (kernel does not necessary switch to this mapping on all interrupts/syscall)
; +-----------------------+
; |```````````````````````| 000000000H (managing physical address directly) 
; |```````````````````````| 
; |```````````````````````| 000100000H (reserved for devices, bios, memory map io, ...)
; |                       | 
; |                       | 
; |                       | 
; |                       |
; |   Identity Mappings   |
; |                       | 
; |                       | 
; |                       | 
; |                       | 
; |                       | 
; |                       | 
; |                       |
; /////////////////////////
; |                       | 0C0000000H (memory here can be fragmented)
; |     Virtual Space     | Here Virtual Space = Kernel Space in all process
; |                       | (All PDE are used to provide this consistency)
; /////////////////////////
; |        Zero PE        | 0FFC00000H
; +-----------------------+

; Some PAE terminology
;  I don't want to waste 1G address space, so I make the paging structure kind of mutually recursive
;  In the PDPT table, I have added an extra slot that point to the PDPT itself, the fifth slot technique
;  But for it to work, I must write to some reserved bit in the PDPTE. So a PDPTE are in "pure" form when all of it's reserved bit are zero

; Some paging terminology
;  The sensitive mapping include two thing:
;   Temporary mapping:
;     1th gen mapping is only useful for clearing a new physicall page when PA != VA
;     2th gen mapping is necessary to copy submapping because pointer can be 36-bit and register are ony 32-bit
;    A maximum of 2 PDE temporary is used because otherwise it's a waste a linear address
;   Recursive mapping are useful to modify the mapping without changing the PDBR
;    Sensitive mapping (temporary mapping and recursive mapping) must be contiguous in the addressing space and are located at the end
;    One property of the recursive mapping must be enforced. The recursive mapping must be linear
;    It's must walk all PTE first, PDE, and PDPTE (PAE) last in that order
;    PSE page are an exception that must be taken into account (No PSE PDE must be treated like a PTE (because of PAT which is not always present))
;    Recursive level mean what [ebx] point to (PTE,PDE,PDPTE)?

_KERNEL_VIRTUAL = 0C0000000H

; 1th generation paging

_TEMP_1_INDEX = (_TABLE_ENTRY_COUNT - 3H)
_TEMP_2_INDEX = (_TABLE_ENTRY_COUNT - 2H)
_PAGE_DIRECTORY_INDEX = (_TABLE_ENTRY_COUNT - 1H)
_RECURSIVE_VIRTUAL = (_PAGE_DIRECTORY_INDEX shl _PAGE_DIRECTORY_SHIFT)
_PAGE_DIRECTORY_LINEAR = (_RECURSIVE_VIRTUAL or (_PAGE_DIRECTORY_INDEX shl _PAGE_TABLE_SHIFT))
_TEMP_MASK = (_PAGE_TABLE_MASK or _PAGE_OFFSET_MASK)
irp _kind*, _TEMP_1,_TEMP_2
{
    _kind#_LINEAR_PTE = (_kind#_INDEX shl _PAGE_DIRECTORY_SHIFT)
    _kind#_LINEAR_PDE = (_RECURSIVE_VIRTUAL or (_kind#_INDEX shl _PAGE_TABLE_SHIFT))
    _kind#_LINEAR_ITSELF = (_PAGE_DIRECTORY_LINEAR or (_kind#_INDEX shl 2H))
}
_KERNEL_VIRTUAL_INDEX = (_KERNEL_VIRTUAL shr _PAGE_DIRECTORY_SHIFT)
_KERNEL_VIRTUAL_COUNT = ((_TABLE_ENTRY_COUNT - _KERNEL_VIRTUAL_INDEX) - 1H)
_PAGE_DIRECTORY_ITSELF = (_PAGE_DIRECTORY_LINEAR or (_PAGE_DIRECTORY_INDEX shl 2H))
_IO_APIC = (_LOCAL_APIC - _PAGE_FRAME_SIZE)
_LOCAL_APIC = (_USER_VDSO_VIRTUAL - _PAGE_FRAME_SIZE)
_USER_VDSO_VIRTUAL = (_FRAME_BUFFER_START - (_PSE_PAGE_FRAME_SIZE shl 1H))
_FRAME_BUFFER_START = (_SENSITIVE_TEMPORARY_START - (_REGEN_4MB_PAGE * _PSE_PAGE_FRAME_SIZE))
_SENSITIVE_TEMPORARY_START = _TEMP_1_LINEAR_PTE
_SENSITIVE_RECURSIVE_START = _RECURSIVE_VIRTUAL
assert (_SENSITIVE_TEMPORARY_START < _SENSITIVE_RECURSIVE_START)

; 2th generation paging

_PDPT_INDEX_KERNEL = 3H
_PDPT_INDEX_RECURSIVE = 4H
_PAE_TEMP_1_INDEX = (_PAE_TABLE_ENTRY_COUNT - 7H)
_PAE_TEMP_2_INDEX  = (_PAE_TABLE_ENTRY_COUNT - 6H)
_PTE_INDEX_RECURSIVE_1 = (_PAE_TABLE_ENTRY_COUNT - 5H)
_PTE_INDEX_RECURSIVE_2 = (_PAE_TABLE_ENTRY_COUNT - 4H)
_PTE_INDEX_RECURSIVE_3 = (_PAE_TABLE_ENTRY_COUNT - 3H)
_PTE_INDEX_RECURSIVE_KERNEL = (_PAE_TABLE_ENTRY_COUNT - 2H)
_PAE_PAGE_DIRECTORY_POINTER_INDEX = (_PAE_TABLE_ENTRY_COUNT - 1H)
_PAE_RECURSIVE_VIRTUAL = ((_PDPT_INDEX_KERNEL shl _PAE_PAGE_DIRECTORY_POINTER_SHIFT) or (_PAE_PAGE_DIRECTORY_POINTER_INDEX shl _PAE_PAGE_DIRECTORY_SHIFT))
_PAE_PDPT_RECURSIVE_VIRTUAL = (_PAE_RECURSIVE_VIRTUAL or (_PDPT_INDEX_RECURSIVE shl _PAGE_TABLE_SHIFT))
_PAE_PTE_RECURSIVE_BASE = ((_PDPT_INDEX_KERNEL shl _PAE_PAGE_DIRECTORY_POINTER_SHIFT) or (_PTE_INDEX_RECURSIVE_1 shl _PAE_PAGE_DIRECTORY_SHIFT))
_PAE_PTE_RECURSIVE_BASE_ITSELF = (_PAE_RECURSIVE_VIRTUAL or (_PDPT_INDEX_KERNEL shl _PAGE_TABLE_SHIFT) or (_PTE_INDEX_RECURSIVE_1 shl 3H))
_PAE_KERNEL_PAGE_DIRECTORY = (_PAE_RECURSIVE_VIRTUAL or (_PDPT_INDEX_KERNEL shl _PAGE_TABLE_SHIFT))
_PAE_TEMP_MASK = (_PAE_PAGE_TABLE_MASK or _PAGE_OFFSET_MASK)
irp _kind*, TEMP_1,TEMP_2
{
    _PAE_#_kind#_LINEAR_PTE = ((_PDPT_INDEX_KERNEL shl _PAE_PAGE_DIRECTORY_POINTER_SHIFT) or (_PAE_#_kind#_INDEX shl _PAE_PAGE_DIRECTORY_SHIFT))
    _PAE_#_kind#_LINEAR_PDE = ((_PDPT_INDEX_KERNEL shl _PAE_PAGE_DIRECTORY_POINTER_SHIFT) or (_PTE_INDEX_RECURSIVE_KERNEL shl _PAE_PAGE_DIRECTORY_SHIFT)\
        or (_PAE_#_kind#_INDEX shl _PAGE_TABLE_SHIFT))
    _PAE_#_kind#_LINEAR_ITSELF = (_PAE_KERNEL_PAGE_DIRECTORY + (_PAE_#_kind#_INDEX shl 3H))
}
_PAE_IO_APIC = (_PAE_LOCAL_APIC - _PAGE_FRAME_SIZE)
_PAE_LOCAL_APIC = (_PAE_USER_VDSO_VIRTUAL - _PAGE_FRAME_SIZE)
_PAE_USER_VDSO_VIRTUAL = (_PAE_FRAME_BUFFER_START - (_PAE_PSE_PAGE_FRAME_SIZE shl 1H))
_PAE_FRAME_BUFFER_START = (_PAE_SENSITIVE_TEMPORARY_START - _PAE_PSE_PAGE_FRAME_SIZE - (_REGEN_4MB_PAGE * _PSE_PAGE_FRAME_SIZE)) ; need to align on _PSE_OFFSET_MASK
_PAE_SENSITIVE_TEMPORARY_START = _PAE_TEMP_1_LINEAR_PTE
_PAE_SENSITIVE_RECURSIVE_START = _PAE_PTE_RECURSIVE_BASE
assert (_PAE_SENSITIVE_TEMPORARY_START < _PAE_SENSITIVE_RECURSIVE_START) 

assert ((_IO_APIC = _PAE_IO_APIC) & (_LOCAL_APIC = _PAE_LOCAL_APIC) & (_USER_VDSO_VIRTUAL = _PAE_USER_VDSO_VIRTUAL))

define _TELETYPE_COUNT 8H
_PAE_TELETYPE_START = 0H ; (_PAE_SENSITIVE_START - (_TELETYPE_COUNT shl ((bsf _PAE_TABLE_ENTRY_COUNT) + _PAGE_TABLE_SHIFT)))

_USER_CODE_VIRTUAL = 8563000H
_USER_SHELL_ARGUMENT_VIRTUAL = (_KERNEL_VIRTUAL - _PAGE_FRAME_SIZE)
_USER_STACK_VIRTUAL = (_USER_SHELL_ARGUMENT_VIRTUAL - _PAGE_FRAME_SIZE)
_KERNEL_STACK_SIZE = _PAGE_FRAME_SIZE

_CODE_KERNEL    = (_kernel_code_segment.selector    + _RPL0)
_DATA_KERNEL    = (_kernel_data_segment.selector    + _RPL0)
_CODE_USER      = (_user_code_segment.selector      + _RPL3)
_DATA_USER      = (_user_data_segment.selector      + _RPL3)
_TSS            = _tss_segment.selector
_CALL_GATE      = _call_gate.selector
_TSS_VM86       = _tss_vm86_segment.selector

_kernel_physical:

struct _linked _prev*, _next*
    .prev:      dd (_prev)
    .next:      dd (_next)
ends

struct _x86_register _edi*, _esi*, _ebp*, _ebx*, _edx*, _ecx*, _eax*, _ds*, _es*, _fs*, _gs*,\
        _trap*, _error*, _eip*, _cs*, _eflags*, _esp*, _ss*
    .edi:       dd (_edi)
    .esi:       dd (_esi)
    .ebp:       dd (_ebp)
                dd 0H
    .ebx:       dd (_ebx)
    .edx:       dd (_edx)
    .ecx:       dd (_ecx)
    .eax:       dd (_eax)
    .ds:        dw (_ds)
                dw 0H
    .es:        dw (_es)
                dw 0H
    .fs:        dw (_fs)
                dw 0H
    .gs:        dw (_gs)
                dw 0H
    .trap:      dd (_trap)
    .error:     dd (_error)
    .eip:       dd (_eip)
    .cs:        dw (_cs)
                dw 0H
    .eflags:    dd (_eflags)
    .esp:       dd (_esp)
    .ss:        dw (_ss)
                dw 0H
ends

struct _vm86_x86_register _edi*, _esi*, _ebp*, _ebx*, _edx*, _ecx*, _eax*, __ds*, __es*, __fs*, __gs*,\
        _trap*, _error*, _eip*, _cs*, _eflags*, _esp*, _ss*, _es*, _ds*, _fs*, _gs*
    .register   _x86_register _edi, _esi, _ebp, _ebx, _edx, _ecx, _eax,\
                    __ds, __es, __fs, __gs, _trap, _error, _eip, _cs, _eflags, _esp, _ss
    .es:        dw (_es)
                dw 0H
    .ds:        dw (_ds)
                dw 0H
    .fs:        dw (_fs)
                dw 0H
    .gs:        dw (_gs)
                dw 0H
ends

struct _debug_context _active*, _dr0*, _dr1*, _dr2*, _dr3*, _dr6*, _dr7*
    .active:    db (_active)
    .dr0:       dd (_dr0)
    .dr1:       dd (_dr1)
    .dr2:       dd (_dr2)
    .dr3:       dd (_dr3)
    .dr6:       dd (_dr6)
    .dr7:       dd (_dr7)
ends

struct _float_context _active*, _save*
    .active:    db (_active)
    .save:      dd (_save) ; either by fxsave or xsave
ends

_current:       dd 0H
_scheduler:     dd 0H
_initproc:      dd 0H

_process_list:  dd 0H
_process_group: dd 0H
_session_list:  dd 0H

_process_dead:  dd 0H
_process_lock:  db 0H ; XXX

struct _page_descriptor _lower*, _upper*, _count*, _lba*, _lock*, _prev*, _next*
    .lower:     dd (_lower) ; physical address low 32-bit
    .upper:     dd (_upper) ; physical address high 32-bit (only if PAE)
    .count:     dd (_count)
    .lba:       dd (_lba)
    .lock:      db (_lock)
    align       4H
    .list       _linked (_prev), (_next)
ends

struct _process_group_descriptor _sid*, _pgid*, _leader*, _prclist*, _stopped*, _orphaned*, _prev_sess, _next_sess, _prev*, _next*
    .sid:       dd (_sid)
    .pgid:      dd (_pgid)
    .leader:    dd (_leader)
    .prclist:   dd (_prclist)
    .stopped:   dd (_stopped) ; count of stopped process in the group
    .orphaned:  db (_orphaned)
    align       4H
    .sess       _linked (_prev_sess), (_next_sess)
    .list       _linked (_prev), (_next)
ends

struct _session_descriptor _sid*, _leader*, _grplist*, _teletype*, _attach*, _prev*, _next*
    .sid:       dd (_sid)
    .leader:    dd (_leader)
    .grplist:   dd (_grplist)
    .teletype:  dd (_teletype)
    .attach:    db (_attach)
    align       4H
    .list       _linked (_prev), (_next)
ends

struct _cpuid _pae*, _maxphyaddr*, _nx*, _pse*, _pse36*, _pge*, _pat*, _popcnt*, _msr*, _xcr0*, _xsave*, _xsaves*,\
        _osxsave*, _apic*, _x2apic*, _direoi*, _sep*, _mtrr*, _wc*, _clflush*, _fixmtrr*, _varmtrr*, _smrr*, _fpu*,\
        _mmx*, _vme*, _de*, _smap*, _smep*, _avx*, _sse*, _sse2*, _sse3*, _ssse3*, _sse41*, _sse42*, _aes*, _pclmulqdq*,\
        _fxsr*, _fsgsbase*, _rdseed*, _sha*, _umip*, _pcid*, _bmi1*, _bmi2*, _vmx*, _mce*, _mca*, _htt*, _acpi*, _lproc*, _linsz*
    .pae:       db (_pae)
    .maxphyaddr:db (_maxphyaddr)
    .nx:        db (_nx)
    .pse:       db (_pse)
    .pse36:     db (_pse36)
    .pge:       db (_pge)
    .pat:       db (_pat)
    .popcnt:    db (_popcnt)
    .msr:       db (_msr)
    .xcr0:      db (_xcr0)
    .xsave:     db (_xsave)     ; user xsave
    .xsaves:    db (_xsaves)    ; supervisor xsave
    .osxsave:   db (_osxsave)
    .apic:      db (_apic)
    .x2apic:    db (_x2apic)
    .direoi:    db (_direoi)
    .sep:       db (_sep)
    .mtrr:      db (_mtrr)
    .wc:        db (_wc)
    .clflush:   db (_clflush)
    .fixmtrr:   db (_fixmtrr)
    .varmtrr:   db (_varmtrr)
    .smrr:      db (_smrr)
    .fpu:       db (_fpu)
    .mmx:       db (_mmx)
    .vme:       db (_vme)
    .de:        db (_de)
    .avx:       db (_avx)
    .sse:       db (_sse)
    .sse2:      db (_sse2)
    .sse3:      db (_sse3)
    .ssse3:     db (_ssse3)
    .sse41:     db (_sse41)
    .sse42:     db (_sse42)
    .aes:       db (_aes)
    .pclmulqdq: db (_pclmulqdq)
    .fxsr:      db (_fxsr)
    .fsgsbase:  db (_fsgsbase)
    .smep:      db (_smep)
    .smap:      db (_smap)
    .rdseed:    db (_rdseed)
    .sha:       db (_sha)
    .umip:      db (_umip)
    .pcid:      db (_pcid)
    .bmi1:      db (_bmi1)
    .bmi2:      db (_bmi2)
    .vmx:       db (_vmx)
    .mce:       db (_mce)
    .mca:       db (_mca)
    .htt:       db (_htt)
    .acpi:      db (_acpi)
    .lproc:     db (_lproc)
    .linsz:     db (_linsz)
ends
assert (_cpuid.sizeof <= 07FH)

_singleton _cpuid 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H,\
    0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H

_memory_size: dd 0H
_kernel_mapping: dd 0H
_kernel_vdso: dq 0H
_page_descriptor_head: dd 0H

irp _kind*, io,local
{
    _#_kind#_apic_base: dd 0H
    _#_kind#_apic_mtrr_alloc: db 0H
    _#_kind#_apic_mtrr_phys: dd 0H
    _#_kind#_apic_mtrr_mask: dd 0H
}
irp _kind*, io_apic,processor { _#_kind#_count: db 0H }

include "fonts.inc"
include "bitmap.inc"

_TELETYPE_TEXT_VIDEO = 00B8000H
_TELETYPE_TEXT_DEFAULT = 00720H
_TELETYPE_VIDEO_FRAME_START = _TELETYPE_GRAPHIC_320x200_VIDEO
_TELETYPE_VIDEO_FRAME_END = _TELETYPE_VIDEO_FRAME_START + 20000H

_TELETYPE_GRAPHIC_320x200_VIDEO = 00A0000H
_TELETYPE_GRAPHIC_320x200_WIDTH = 140H
_TELETYPE_GRAPHIC_320x200_HEIGHT = 0C8H
_TELETYPE_GRAPHIC_320x200_SCANLINE = 140H
_TELETYPE_GRAPHIC_320x200_PITCH = 8H
_TELETYPE_GRAPHIC_320x200_RESOLUTION = 013H

_TELETYPE_GRAPHIC_XORED = 080H
_TELETYPE_NULL_POSITION = (not 0H)
_TELETYPE_REGEN = 10000H

_MAX_COLOR = 010H

enum _VGA_BLACK, _VGA_BLUE, _VGA_GREEN, _VGA_CYAN, _VGA_RED, _VGA_MAGENTA, _VGA_BROWN, _VGA_LIGHT_GRAY, _VGA_DARK_GRAY,\
    _VGA_LIGHT_BLUE, _VGA_LIGHT_GREEN, _VGA_LIGHT_CYAN, _VGA_LIGHT_RED, _VGA_LIGHT_MAGENTA, _VGA_YELLOW, _VGA_WHITE

_RGB_BLACK = _VGA_BLACK
_RGB_BLUE = 00000AAH
_RGB_GREEN = 000AA00H
_RGB_CYAN = 000AAAAH
_RGB_RED = 0AA0000H
_RGB_MAGENTA = 0AA00AAH
_RGB_BROWN = 0AA5500H
_RGB_LIGHT_GRAY = 0AAAAAAH
_RGB_DARK_GRAY = 0555555H
_RGB_LIGHT_BLUE = 05555FFH
_RGB_LIGHT_GREEN = 055FF55H
_RGB_LIGHT_CYAN = 055FFFFH
_RGB_LIGHT_RED = 0FF5555H
_RGB_LIGHT_MAGENTA = 0FF55FFH
_RGB_YELLOW = 0FFFF55H
_RGB_WHITE = 0FFFFFFH

enum _TELETYPE_TEXT_40x25:1H, _TELETYPE_TEXT_80x25:3H, _TELETYPE_GRAPHIC_40x25:013H
enum & IGNBRK, BRKINT, IGNPAR, PARMRK, INPCK, ISTRIP, INLCR, IGNCR, ICRNL, IUCLC, IXON, IXANY, IXOFF, IMAXBEL, IUTF8    
enum & OPOST, OLCUC, ONLCR, OCRNL
enum & CBAUD, CS8, CBAUDEX
enum & ISIG, ICANON, XCASE, ECHO, ECHOE, ECHOK, ECHONL, NOFLSH, TOSTOP, ECHOCTL, ECHOPRT, ECHOKE, FLUSHO, PENDIN, IEXTEN, EXTPROC

struct _termios _iflag*, _oflag*, _cflag*, _lflag*, _vmin*, _veol*, _vintr*, _vquit*, _verase*, _vkill*, _veof*, _vstart*,\
        _vstop*, _vsusp*, _vlnext*, _vwerase*, _vreprint*
    .iflag:     dw (_iflag)
    .oflag:     dw (_oflag)
    .cflag:     dw (_cflag)
    .lflag:     dw (_lflag)
    .vmin:      dw (_vmin)
    .veol:      db (_veol)
    .vintr:     db (_vintr)
    .vquit:     db (_vquit)
    .verase:    db (_verase)
    .vkill:     db (_vkill)
    .veof:      db (_veof)
    .vstart:    db (_vstart)
    .vstop:     db (_vstop)
    .vsusp:     db (_vsusp)
    .vlnext:    db (_vlnext)
    .vwerase:   db (_vwerase)
    .vreprint:  db (_vreprint)
ends

_DEFAULT_IFLAG = (ICRNL or IXON)
_DEFAULT_OFLAG = (OPOST or ONLCR)
_DEFAULT_CFLAG = (CS8)
_DEFAULT_LFLAG = (ISIG or ICANON or ECHO or ECHOE or ECHOK or ECHONL or ECHOCTL or ECHOKE or IEXTEN)
_default_termios _termios _DEFAULT_IFLAG, _DEFAULT_OFLAG, 0DEADH, _DEFAULT_LFLAG, 0H, 0H, 3H, 01CH, 07FH, 015H, 4H, 011H, 013H, 01AH, 016H, 017H, 012H

_TELETYPE_INPUT = _PAGE_FRAME_SIZE
assert (_TELETYPE_INPUT = _PAGE_FRAME_SIZE)

struct _teletype _input*, _regen*, _video*, _index*, _ceidx*, _gfxpos*, _gfxwdth*, _gfxhght*, _position*, _width*, _height*, _eoi*, _mode*, _init*, _id*,\
        _fonts_source*, _fonts_width*, _fonts_height*, _fonts_btposw*, _fonts_btposh*, _scroll*, _cursor*, _tabulation*,\
        _xlinear*, _ylinear*, _xgrid*, _ygrid*, _backgnd*, _foregnd*,\
        _iflag*, _oflag*, _cflag*, _lflag*, _vmin*, _veol*, _vintr*, _vquit*, _verase*, _vkill*, _veof*, _vstart*, _vstop*, _vsusp*, _vlnext*, _vwerase*, _vreprint*
    .input:     dd (_input)
    .regen:     dd (_regen)
    .video:     dd (_video)
    .index:     dw (_index)
    .ceidx:     dw (_ceidx) ; cannonical end of input index

    .gfxpos:    dd (_gfxpos)
    .gfxwdth:   db (_gfxwdth)
    .gfxhght:   db (_gfxhght)
    .position:  dw (_position)
    .width:     db (_width) ; needed to see if the cursor is located on the last column of the current row
    .height:    db (_height) ; needed for cursor to be redrawn in graphic mode

    .fonts      _fonts (_fonts_source), (_fonts_width), (_fonts_height), (_fonts_btposw), (_fonts_btposh)
    .scroll:    dd (_scroll)
    .xlinear:   dw (_xlinear)
    .ylinear:   dw (_ylinear)
    .xsaved:    dw 0H
    .ysaved:    dw 0H
    .xgrid:     dw (_xgrid)
    .ygrid:     dw (_ygrid)
    .backgnd:   dd (_backgnd) ; background color
    .foregnd:   dd (_foregnd) ; foreground color

    .cursor:    db (_cursor)
    .tabulation:db (_tabulation)
    .vdfrbf:    db 0H
    .legacy:    db 0H

    .sesdesc:   dd 0H ; session attached to this teletype
    .grpdesc:   dd 0H ; foreground group
    .control:   db 0H ; is a controlling terminal
    .fground:   db 0H ; have a foreground group which signal are send

    .attach:    dd 0H ; (_attach)
    
    .eoi:       db (_eoi) ; only useful with _TELETYPE_ICANON, 0H to indicate the user has not typed enter (does not take into account ^V^J)
    .vbe:       db 0H
    .mode:      db (_mode)
    .init:      db (_init)
    .id:        db (_id)

    .idxstp:    dw (0H)

    .termios    _termios _iflag, _oflag, _cflag, _lflag, _vmin, _veol, _vintr, _vquit, _verase, _vkill, _veof, _vstart, _vstop, _vsusp, _vlnext, _vwerase, _vreprint
ends

align 4H
_teletype_table:
rept _TELETYPE_COUNT i:1H { dd _tty#i }
_teletype_table_end:
rept _TELETYPE_COUNT i:1H
{
    _TTY#i = (i - 1H)
    _tty#i _teletype 0H, 0H, _TELETYPE_TEXT_VIDEO, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, _TELETYPE_TEXT_80x25, 0H, (i - 1H),\
        0H, 0H, 0H, 0H, 0H, 0H, -1H, 4H, 0H, 0H, 0H, 0H, (i - 1H), 0FF00H, ICRNL,\
        OPOST, 0H, (ICANON or ECHO or ECHOE or ECHONL), 0H, 0H, 3H, 01CH, 07FH, 015H, 4H, 011H, 013H, 01AH, 016H, 017H, 012H
}

_current_teletype:  dd 0H
_vbe_frame_amount:  dd 0H
_current_modeinfo   _mode_info_block 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H,\
                        0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H

struct _kbdste _extended*, _scroll_lock*, _right_ctrl*, _left_ctrl*, _right_shift*,\
        _left_shift*, _right_alt*, _left_alt*, _caps_lock*, _num_lock*
    .extended:      db (_extended)
    .scroll_lock:   db (_scroll_lock)
    .right_ctrl:    db (_right_ctrl)
    .left_ctrl:     db (_left_ctrl)
    .right_shift:   db (_right_shift)
    .left_shift:    db (_left_shift)
    .right_alt:     db (_right_alt)
    .left_alt:      db (_left_alt)
    .caps_lock:     db (_caps_lock)
    .num_lock:      db (_num_lock)
ends

_current_keyboard   _kbdste 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H

_PROCESS_STRING     = 020H
_PROCESS_CHANNEL    = 0H
_PROCESS_POLICY     = 0H
_PROCESS_NICE       = 5H
_PROCESS_WAITABLE   = (not 0H)
_PROCESS_ZOMBIES    = (not 0H)
_PROCESS_STACKPF    = 020H ; 32 page by default allowed to be allocated on page fault

struct _signal_context _handler*, _sigframe*, _newfrm*, _assign*, _nested*
    .handler:   dd (_handler)
    .sigframe:  dd (_sigframe)
    .newfrm:    db (_newfrm)
    .assign:    db (_assign)
    .nested:    db (_nested)
    align       010H
ends
assert (_signal_context.sizeof = 010H)

struct _socket _filde*, _lock*, _bind*, _port*, _buffer*, _cursor*, _stand*, _prev*, _next*
    .filde:     dd (_filde)
    .lock:      db (_lock)
    .bind:      db (_bind)
    .port:      dw (_port)
    .buffer:    dd (_buffer)
    .cursor:    dd (_cursor)
    .stand:     dd (_stand)
    .list       _linked (_prev), (_next)
ends

include "signal_enum.inc"

_PROCESS_SIGNALS_BITMAP = ((_SIGNALS + (_BITMAP_UNIT - 1H)) and (not (_BITMAP_UNIT - 1H)))
_PORT_RANGE = (_PORT_AVAILABLE shr 3H)

enum _PROCESS_RUN, _PROCESS_ZOMBIE, _PROCESS_SLEEP, _PROCESS_STOP, _PROCESS_DEAD, _PROCESS_THREAD
struct _process _state*, _pid*, _uid*, _pgid*, _sid*, _tid*, _mnbrk*, _break*, _ustck*, _mapping*, _parent*, _childs*, _socket*, _sockno*, _sesdesc*, _grpdesc*,\
        _siblings_prev*, _siblings_next*, _pgroup_prev*, _pgroup_next*, _stackpf*, _pfcount*, _sigcnt*, _signst*, _sigstp*, _tty*, _waitable*, _jststp*, _jstcnt*,\
        _vm86*, _vmflgs*, _lwreal*, _hgreal*, _mapreal*, _lckreal*, _vif*, _vip*, _extcde*, _extsig*, _fground_prev*, _fground_next*, _priority*, _increment*, _intprec*, _channel*,\
        _kstack*, _vstack*, _pgstck*, _retframe*, _vmframe*, _context*, _list_prev*, _list_next*, _name*
    .state:     dd (_state)
    .pid:       dd (_pid)
    .uid:       dd (_uid)
    .pgid:      dd (_pgid)
    .sid:       dd (_sid)
    .tid:       dd (_tid)
    .mnbrk:     dd (_mnbrk) ; the minimum value of program break
    .break:     dd (_break) ; program break
    .ustck:     dd (_ustck) ; always decrement never increment
    .mapping:   dd (_mapping)
    .parent:    dd (_parent)
    .childs:    dd (_childs)
    .socket:    dd (_socket)
    .sockno:    dd (_sockno)
    .sesdesc:   dd (_sesdesc)
    .grpdesc:   dd (_grpdesc)
    .siblings   _linked _siblings_prev, _siblings_next
    .pgroup     _linked _pgroup_prev, _pgroup_next
    .stackpf:   dd (_stackpf) ; max allowed stack page fault (-1 for page fault until stack meet the program break)
    .pfcount:   dd (_pfcount) ; how many this process has performed a page fault
    .sigmask    _bitmap _PROCESS_SIGNALS_BITMAP
    .pending    _bitmap _PROCESS_SIGNALS_BITMAP
    .signals:   dd ((_SIGNALS+1H) shl (bsf _signal_context.sizeof)) dup 0H
    .sigcnt:    dd (_sigcnt) ; count of received signal even if it's blocked with sigmask
    .signst:    db (_signst) ; signal nested counter
    .sigstp:    db (_sigstp) ; signal that caused a stop
    .ports      _bitmap _PORT_RANGE
    .waitable:  db (_waitable)
    .vm86:      db (_vm86)
    .vmflgs:    dd (_vmflgs)
    .lwreal:    dd (_lwreal)
    .hgreal:    dd (_hgreal)
    .mapreal:   db (_mapreal)
    .lckreal:   db (_lckreal)
    .vif:       db (_vif)
    .vip:       db (_vip)

    .daemon:    db 0H ; if it's attached to a TTY
    .allzmbs:   db 0H ; if all children of this process are zombie ? 0H if the process has not children

    .tty:       dd (_tty)
    ;.jststp:    dw (_jststp)
    ;.jstcnt:    dw (_jstcnt)
    .refresh:   db 0H ; need to refresh the PSE page framebuffer because the resolution has changed

 
    .seslead:   db 0H
    .grplead:   db 0H
    .panic:     db 0H

    ;.fsave:
    ;.fxsave:    dd (0H)
    ;.extwhy:    dd (0H)

    .fltctx     _float_context 0H, 0H
    .dbgctx     _debug_context 0H, 0H, 0H, 0H, 0H, 0H, 0H
    .align:     db 0H

    .extcde:    dd (_extcde)
    .extsig:    db (_extsig)

    ;.fground    _linked _fground_prev, _fground_next
    .priority:  dd (_priority)
    .increment: dd (_increment)
    .intprec:   db (_intprec)
    .channel:   dd (_channel)
    .kstack:    dd (_kstack) ; kernel task stack (in TSS.esp0)
    .vstack:    dd (_vstack)
    .pgstck:    dd (_pgstck) ; page wher the stack reside
    .retframe:  dd (_retframe) ; point into kernel task stack where user register reside
    .vmframe:   dd (_vmframe) ; virtual 8086 task stack
    .context:   dd (_context) ; point into kernel task stack where a saved eip reside (context switch entry point)
    .list       _linked _list_prev, _list_next
    .name       string _name
    times       (_PROCESS_STRING - .name.sizeof) db 0H ; XXX
ends

struct _pci_configuration_header _vendor_id*, _device_id*, _command_register*, _status_register*, _revision_id*,\
        _class_code*, _cache_line_size*, _latency_timer*, _header_type*, _bist*
    .vendor_id:         dw (_vendor_id)
    .device_id:         dw (_device_id)
    .command_register:  dw (_command_register)
    .status_register:   dw (_status_register)
    .revision_id:       db (_revision_id)
    .class_code:        dw ((_class_code) and 0FFFFH)
                        db ((_class_code) shr 010H)
    .cache_line_size:   db (_cache_line_size)
    .latency_timer:     db (_latency_timer)
    .header_type:       db (_header_type)
    .bist:              db (_bist)
ends

struct _pci_header_device _vendor_id*, _device_id*, _command_register*, _status_register*, _revision_id*,\
        _class_code*, _cache_line_size*, _latency_timer*, _bist*, _bar0*, _bar1*, _bar2*, _bar3*, _bar4*, _bar5*,\
        _cardbus_cis*, _subsystem_vendor_id*, _subsystem_id*, _expansion_rom*, _capabilities*, _interrupt_line*,\
        _interrupt_pin*, _min_gnt*, _max_lat*
    .header                 _pci_configuration_header _vendor_id, _device_id, _command_register, _status_register,\
                                _revision_id, _class_code, _cache_line_size, _latency_timer, _PCI_HEADER_DEVICE, _bist
    .bar0:                  dd (_bar0)
    .bar1:                  dd (_bar1)
    .bar2:                  dd (_bar2)
    .bar3:                  dd (_bar3)
    .bar4:                  dd (_bar4)
    .bar5:                  dd (_bar5)
    .cardbus_cis:           dd (_cardbus_cis)
    .subsystem_vendor_id:   dw (_subsystem_vendor_id)
    .subsystem_id:          dw (_subsystem_id)
    .expansion_rom:         dd (_expansion_rom)
    .capabilities:          db (_capabilities)
    .reserved:              db 7H dup 0H
    .interrupt_line:        db (_interrupt_line)
    .interrupt_pin:         db (_interrupt_pin)
    .min_gnt:               db (_min_gnt)
    .max_lat:               db (_max_lat)
ends

_frame _bitmap ((200000000H shr 00CH) shr 3H)
_pid_table _bitmap 080H

_kernel_entry:
    cli
    call _idt_reset
    mov al, _INTEL_RESERVED_INT
    call _8259_enable
    call _configure_8253
    test byte [_singleton.xsave], 1H
    jz _kernel_entry_xsave
    test byte [_singleton.sse], 1H
    jz _kernel_entry_xsave
    test byte [_singleton.xsaves], 1H
    jz _kernel_entry_rfbm
    xor edx, edx
    xor eax, eax
    mov ecx, _IA32_XSS
    wrmsr
_kernel_entry_rfbm:
    xor ecx, ecx
    mov cl, _XCR0
    xgetbv
    or al, _XCR0_SSE
    test byte [_singleton.avx], 1H
    jz _kernel_entry_xcr0_write
    or al, _XCR0_AVX
_kernel_entry_xcr0_write:
    xsetbv
_kernel_entry_xsave:
    test byte [_singleton.pae], 1H
    jz _kernel_entry_efer
    test byte [_singleton.nx], 1H
    jz _kernel_entry_efer
    mov ecx, _EFER
    rdmsr
    or eax, _EFER_NXE
    wrmsr
_kernel_entry_efer:
    _load_descriptor_table gdt, _GDT
    _load_descriptor_table idt, _IDT
    mov ax, _TSS
    ltr ax
    xor ax, ax  
    lldt ax
    jmp far _CODE_KERNEL:_kernel_entry_setup
_kernel_entry_setup:
    mov ax, _DATA_KERNEL
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    finit
    test byte [_singleton.sse], 1H
    jz _kernel_entry_default
    ldmxcsr dword [_default_mxcsr]
_kernel_entry_default:
    call _kernel_enable_nmi
    ;call _debug_force_reset
    xor eax, eax
    mov al, _DEBUG_RW_INST_READ
    xor ebx, ebx
    xor ecx, ecx
    ;call _debug_memory_range
    xor eax, eax
    xor edx, edx
    mov ecx, _KERNEL_GS_BASE
    call _write_msr
    mov ecx, _IA32_MISC_ENABLE
    call _read_msr
    jc _kernel_entry_smp
    or al, (_MISC_FAST_STRING_ENABLE or _MISC_ENABLE_THERMAL_MONITOR)
    wrmsr

    ;sub esp, 2H
    ;fnstcw word [esp]
    ;and word [esp], (not _FCW_ZM)
    ;fldcw word [esp]
    ;fldz
    ;fld1
    ;fdiv st0, st1
    ;fwait

    ;mov edi, _fpu_init
    ;fxsave [edi]
    ;mov eax, _local_apic_base
    ;xor ecx, ecx
    ;xor edx, edx
    ;monitor eax, ecx, edx
    ;xor eax, eax
    ;xor ecx, ecx
    ;mwait eax, ecx

    ;mov eax, cr4
    ;or eax, _CR4_SMAP
    ;mov cr4, eax
    ;clac
    ;mov al, byte [esp]
    ;mov byte [esp], 0H
    ;stac

_kernel_entry_smp:
    ;mov eax, _extract_primary_apic_information
    ;call _parse_mp_conftable_entry

    mov eax, _frame
    mov ebx, dword [_frame.next]
    mov ecx, ((_KERNEL_IDENTITY * _PSE_PAGE_FRAME_SIZE) shr _PAGE_TABLE_SHIFT)
    xor edx, edx
    mov edi, _BITMAP_RESET
    call _bitmap_update
    jc _panic
    call _pdpt_read_write_current
    mov eax, cr3
    and eax, (not _PAGE_OFFSET_MASK)
    mov dword [_kernel_mapping], eax
    call _initialize_multitasking
    jc _panic

    ;xor ebx, ebx
    ;mov bl, _SCHEDULER_PID
    ;call _syscall_daemon
    ;xor ebx, ebx
    ;mov bl, _INIT_PID
    ;call _syscall_daemon

    call _teletype_initialize
    jc _panic
    ;xor eax, eax
    ;call _refresh_apic_registers_set
    ;jc _panic
    ;call _soft_enable_apic
    call _create_vdso
    jc _panic

match,DEBUG
{
    cmp dword [_io_apic_count], 0H
    jz _kernel_entry_uniprocessor
    mov eax, _configure_io_apic_rt
    mov edi, [_PAE_LOCAL_APIC+_LOCAL_APIC_ID_REGISTER]
    xor ebp, ebp
    call _parse_mp_conftable_entry
_kernel_entry_uniprocessor:
    mov eax, dword [_rsdp_descriptor_base]
    mov ebx, dword [eax+_rsdp_descriptor.rsdt_address]
    mov edx, _MADT
    call _acpi_find_sdt_table
    mov ecx, dword [ebx+_madt_header.common.length]
    sub ecx, _madt_header.sizeof
    lea ebx, [ebx+_madt_header.sizeof]
_abc_loop:
    mov dl, byte [ebx+_madt_prefix.type]
    cmp dl, _MADT_PROCESSOR_LOCAL_APIC
    jz _abc_preprocessor
    cmp dl, _MADT_IO_APIC
    jz _abc_io_apic
_abc_preprocessor:
    inc byte [_processor_count]
    jmp _abc_update
_abc_io_apic:
    inc byte [_io_apic_count]
    mov edx, dword [ebx+_madt_io_apic.io_apic_address]
    mov dword [_io_apic_base], edx
    xor eax, eax
    mov al, _REFRESH_ONLY_IO_APIC
    call _refresh_apic_registers_set
    call _io_apic_reset_rt
    call _io_apic_irq_connect
    call _8259_disable
    ;call _soft_disable_apic
    ;mov dword [_LOCAL_APIC+_SPURIOUS_INTERRUPT_VECTOR_REGISTER], 0H
    ;mov eax, dword [_LOCAL_APIC+_SPURIOUS_INTERRUPT_VECTOR_REGISTER]
    ;mov eax, dword [_LOCAL_APIC+_LVT_LINT0]
    ;xor eax, _LVT_LINT_MASKED
    ;mov dword [_LOCAL_APIC+_LVT_LINT0], eax
    ;mov eax, dword [_LOCAL_APIC+_LVT_LINT0]

    mov ecx, _IA32_APIC_BASE
    rdmsr
    or eax, (_APIC_BASE_EN or _APIC_BASE_EXTD)
    wrmsr

    sub esp, _pci_configuration_header.sizeof
    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx
    mov esi, esp
    call _pci_read_configuration_header

    call _set_cr0_am
    mov eax, _EFLAGS_AC
    call _set_eflags
    mov dword [1H], 5H

    mov eax, 0H
    mov ebx, 01FH
    mov ecx, 7H
    xor edx, edx
    mov edi, 0H
    call _pci_write_configuration_space

    mov ebx, _LOCAL_APIC_ACCESS_WRITE
    mov ecx, _LVT_ERROR
    mov eax, _APIC_ERROR_ENTRY
    call _local_apic_access_register

    mov eax, _APIC_ERROR_ENTRY
    mov edx, (_apic_error_gate or _SWAP_IDT_ASSIGN_GATE)
    call _set_and_swap_idt_vector
    ;mov ecx, 

    xor eax, eax
    cpuid
    mov eax, 0BH
    xor ecx, ecx
    cpuid

    ;mov dword [_LOCAL_APIC+_LOGICAL_DESTINATION_REGISTER], (0DAH shl 018H)
    ;mov eax, 1H
    ;cpuid

    ;mov dword [_LOCAL_APIC+_ERROR_STATUS_REGISTER], 1H
    ;mov eax, dword [_LOCAL_APIC+_ERROR_STATUS_REGISTER]
    ;mov al, byte [_singleton.x2apic]
    mov ecx, (_LOCAL_APIC_BASE_MSR + _LOGICAL_DESTINATION_REGISTER_MSR)
    rdmsr
    jmp $

    mov ecx, (_LOCAL_APIC_BASE_MSR + _LVT_ERROR_MSR)
    rdmsr
    mov edx, 5H
    wrmsr
    mov ecx, (_LOCAL_APIC_BASE_MSR + _INTERRUPT_COMMAND_REGISTER_MSR)
    xor edx, edx
    mov eax, (_ICR_SELF or _ICR_LEVEL_ASSERT or 3H)
    wrmsr

    ;mov ecx, _SELF_IPI
    ;xor eax, eax
    ;xor edx, edx
    ;mov al, 0H
    sti
    nop
    nop
    mov ecx, (_LOCAL_APIC_BASE_MSR + _LVT_ERROR_MSR)
    rdmsr
    mov ecx, (_LOCAL_APIC_BASE_MSR + _ERROR_STATUS_REGISTER_MSR)
    xor eax, eax
    wrmsr
    rdmsr
    xor eax, eax
    wrmsr
    rdmsr
    ;wrmsr
    ;mov ecx, (_LOCAL_APIC_BASE_MSR + _ERROR_STATUS_REGISTER_MSR)
    ;xor eax, eax
    ;xor edx, edx
    ;wrmsr
    ;rdmsr
    jmp $

    mov al, byte [_singleton.acpi]
    mov ecx, 19CH
    rdmsr

    mov dword [_IO_APIC+_INDEX_REGISTER], _IO_APIC_RT_LOW_1
    mov eax, dword [_IO_APIC+_DATA_REGISTER]
    mov dword [_IO_APIC+_INDEX_REGISTER], _IO_APIC_RT_LOW_2
    mov eax, dword [_IO_APIC+_DATA_REGISTER]

    ;sti
    ;jmp $
    jmp __next

;_oo_loop:
;    mov al, _IO_APIC_RT_HIGH_2
;    mov byte [_PAE_IO_APIC+_INDEX_REGISTER], al
;    mov eax, dword [_PAE_IO_APIC+_DATA_REGISTER]
;    test eax, 1 shl 12
;    jz _oo_loop
;    nop

_abc_update:
    movzx eax, byte [ebx+_madt_prefix.length]
    sub ecx, eax
    add ebx, eax
    test ecx, ecx
    jnz _abc_loop

__next:

    mov dword [_PAE_LOCAL_APIC+_LOCAL_EOI_REGISTER], 0H
    call _8259_disable
    mov byte [_PAE_IO_APIC+_INDEX_REGISTER], _REDIRECTION_TABLE_BASE
    mov eax, dword [_PAE_IO_APIC+_DATA_REGISTER]
    mov byte [_PAE_IO_APIC+_INDEX_REGISTER], _REDIRECTION_TABLE_BASE+1H
    mov eax, dword [_PAE_IO_APIC+_DATA_REGISTER]
    sti
    jmp $


    jmp $
    
    mov word [0DEADH], 0FEEBH
    mov al, _RESET_CODE_BYTE
    out _CMOS_SELECT, al
    mov al, _BIOS_JUMP_EOI
    out _CMOS_PORT, al
    mov dword [_WARN_RESET_VECTOR], 0DEADH
    call _reboot_system
    jmp $

    mov eax, _next
    ;mov word [_interrupt_stub_49], 0E0FFH
    mov edx, dword [_PAE_LOCAL_APIC+_LOCAL_APIC_ID_REGISTER]
    shl edx, (_ICR_XAPIC_DESTINATION_SHIFT - 020H)
    mov dword [_PAE_LOCAL_APIC+_INTERRUPT_COMMAND_REGISTER_HIGH], edx
    mov dword [_PAE_LOCAL_APIC+_INTERRUPT_COMMAND_REGISTER_LOW], (_LVT_LINT_DELIVERY_INIT)
    sti
    jmp $

_next:
    mov eax, dword [_PAE_LOCAL_APIC+_INTERRUPT_COMMAND_REGISTER_LOW]

    ;mov dword [_PAE_LOCAL_APIC+_LVT_LINT0], (_LVT_LINT_LEVEL_SENSITIVE or 031H)

    mov dword [_PAE_LOCAL_APIC+_TASK_PRIORITY_REGISTER], (2H shl 4H)
    mov dword [_PAE_LOCAL_APIC+_LVT_TIMER], 031H
    mov dword [_PAE_LOCAL_APIC+_TIMER_DIVIDE_CONFIG_REGISTER], _LVT_TIMER_DIVIDE_2
    mov dword [_PAE_LOCAL_APIC+_TIMER_INITIAL_COUNT_REGISTER], 100H
    ;sti
    mov eax, dword [_PAE_LOCAL_APIC+_LVT_TIMER]
_loop:
    mov eax, dword [_PAE_LOCAL_APIC+_TIMER_CURRENT_COUNT_REGISTER]
    ;test eax, eax
    ;jz _j
    jmp _loop
}

    test byte [_singleton.sep], 1H
    jz _kernel_entry_sysenter
    xor edx, edx
    mov eax, _CODE_KERNEL
    mov ecx, _SYSENTER_CS_MSR
    wrmsr
    mov eax, _sysenter_entry
    mov ecx, _SYSENTER_EIP_MSR
    wrmsr
    xor eax, eax
    mov ecx, _SYSENTER_ESP_MSR
    wrmsr
_kernel_entry_sysenter:
    mov byte [_singleton.apic], 0H
    mov byte [_singleton.x2apic], 0H

    mov ax, 013H
    call _video_bios
    jc _teletype_initialize_exit

    mov eax, _VGA_RED
    mov ebx, _tty1
    mov edx, _VGA_GREEN
    call _teletype_set_color

    mov word [_current_modeinfo.bytes_scanline], _TELETYPE_GRAPHIC_320x200_SCANLINE
    mov word [_current_modeinfo.x_resolution], _TELETYPE_GRAPHIC_320x200_WIDTH
    mov word [_current_modeinfo.y_resolution], _TELETYPE_GRAPHIC_320x200_HEIGHT
    mov dword [_current_modeinfo.physical], _TELETYPE_GRAPHIC_320x200_VIDEO
    mov byte [_current_modeinfo.bits_pixel], _TELETYPE_GRAPHIC_320x200_PITCH
    mov byte [_tty1.legacy], (not 0H)

    call _refresh_resolution

    mov ebx, _tty1
    mov esi, _default_font_8x8
    xor ecx, ecx
    call _teletype_set_font

    mov byte [_tty1.legacy], 0H
    mov dword [_tty1.backgnd], _RGB_BLACK
    mov dword [_tty1.foregnd], _RGB_GREEN

    mov eax, _VIDEO_MODE_WIDTH
    mov edx, _VIDEO_MODE_HEIGHT

    call _search_vbe_mode
    js _kernel_entry_next
    jc _panic
    call _refresh_resolution
    jc _panic
_kernel_entry_next:
    mov eax, _SYSCALL_EXEC
    mov ebx, _init_payload
    mov ecx, _init.sizeof
    push eax eax ; emulate the privilege change stack layout
    ;test byte [_singleton.smap], 1H
    ;clac
    int 030H
    jmp _kernel_error

_cpuid_detection:
 ; in: esi - cpuid state object
 ; out: cf - set if cpuid not supported
 ; preserves: ebx, ecx, edx, esi, edi, ebp
 ; note:
 ;  Avoid to execute cpuid as much as possible, it's a serialization instruction (out-of-order are disable)
 ;  To ensure that cpuid is present, I update the EFLAGS[ID] to see if it's change.
 ;  Warning: Do not depend on the absence of an invalid opcode trap on the CPUID opcode to detect the CPUID instruction.
    push ebx ecx edx edi ebp
    mov byte [esi+_cpuid.maxphyaddr], 020H
 irp _kind*, or,xor
 {
    pushfd
    _kind dword [esp], _EFLAGS_CPUID
    popfd
    pushfd
    pop eax
    test eax, _EFLAGS_CPUID
    stc
    match =or,  _kind \{ jz  _cpuid_detection_exit \}
    match =xor, _kind \{ jnz _cpuid_detection_exit \}
 }
    xor ecx, ecx
    mov cl, _cpuid.sizeof
    call _clear_string
    xor eax, eax
    cpuid
    mov edi, eax
    mov eax, (1H shl 01FH)
    cpuid
    mov ebp, eax
    xor eax, eax
    mov al, _CPUID_LEAF_PROCESSOR_INFO
  assert ((_CPUID_LEAF_PROCESSOR_INFO < _CPUID_LEAF_EXTEND_FEATURE) &\
        (_CPUID_LEAF_EXTEND_FEATURE < _CPUID_LEAF_EXTEND_STATE))
    cmp eax, edi
    ja _cpuid_detection_extended
    cpuid
    test edx, _CPUID_EDX_FPU
    jz $+5H
    inc byte [esi+_cpuid.fpu]
    test edx, _CPUID_EDX_VME
    jz $+5H
    inc byte [esi+_cpuid.vme]
    test edx, _CPUID_EDX_PSE
    jz $+5H
    inc byte [esi+_cpuid.pse]
    test edx, _CPUID_EDX_MSR
    jz $+5H
    inc byte [esi+_cpuid.msr]
    test edx, _CPUID_EDX_PAE
    jz $+4H
  assert (_cpuid.pae = 0H)
    inc byte [esi+_cpuid.pae]
    test edx, _CPUID_EDX_MCE
    jz $+5H
    inc byte [esi+_cpuid.mce]
    test edx, _CPUID_EDX_APIC
    jz $+5H
    inc byte [esi+_cpuid.apic]
    test edx, _CPUID_EDX_SEP ; sysenter/sysexit
    jz $+5H
    inc byte [esi+_cpuid.sep]
    test edx, _CPUID_EDX_MTRR
    jz $+5H
    inc byte [esi+_cpuid.mtrr]
    test edx, _CPUID_EDX_PGE
    jz $+5H
    inc byte [esi+_cpuid.pge]
    test edx, _CPUID_EDX_MCA
    jz $+5H
    inc byte [esi+_cpuid.mca]
    test edx, _CPUID_EDX_PAT
    jz $+5H
    inc byte [esi+_cpuid.pat]
    test edx, _CPUID_EDX_PSE36
    jz $+5H
    inc byte [esi+_cpuid.pse36]
    test edx, _CPUID_EDX_FXSR
    jz $+5H
    inc byte [esi+_cpuid.fxsr]
    test edx, _CPUID_EDX_HTT
    jz _cpuid_detection_flush
    inc byte [esi+_cpuid.htt]
    mov eax, ebx
    and eax, _CPUID_EBX_LPROCMSK
    shr eax, _CPUID_EBX_LPROCSHT
    mov byte [esi+_cpuid.lproc], al
_cpuid_detection_flush:
    test edx, _CPUID_EDX_CLFLUSH
    jz _cpuid_detection_smid
    inc byte [esi+_cpuid.clflush]
    mov eax, ebx
    and eax, _CPUID_EBX_LINSZMSK
    shr eax, (_CPUID_EBX_LINSZSHT - 3H)
  assert (_CPUID_EBX_LINSZSHT > 3H)
    mov byte [esi+_cpuid.linsz], al
_cpuid_detection_smid:
    test edx, _CPUID_EDX_MMX
    jz $+5H
    inc byte [esi+_cpuid.mmx]
    test edx, _CPUID_EDX_SSE
    jz $+5H
    inc byte [esi+_cpuid.sse]
    test edx, _CPUID_EDX_SSE2
    jz $+5H
    inc byte [esi+_cpuid.sse2]
    test ecx, _CPUID_ECX_SSE3
    jz $+5H
    inc byte [esi+_cpuid.sse3]
    test ecx, _CPUID_ECX_PCLMULQDQ
    jz $+5H
    inc byte [esi+_cpuid.pclmulqdq]
    test ecx, _CPUID_ECX_SSSE3
    jz $+5H
    inc byte [esi+_cpuid.ssse3]
    test ecx, _CPUID_ECX_SSE41
    jz $+5H
    inc byte [esi+_cpuid.sse41]
    test ecx, _CPUID_ECX_SSE42
    jz $+5H
    inc byte [esi+_cpuid.sse42]
    test edx, _CPUID_EDX_ACPI
    jz $+5H
    inc byte [esi+_cpuid.acpi]
    test ecx, _CPUID_ECX_VMX
    jz $+5H
    inc byte [esi+_cpuid.vmx]
    test ecx, _CPUID_ECX_PCID
    jz $+5H
    inc byte [esi+_cpuid.pcid]
    test ecx, _CPUID_ECX_X2APIC
    jz $+5H
    inc byte [esi+_cpuid.x2apic]
    test ecx, _CPUID_ECX_POPCNT
    jz $+5H
    inc byte [esi+_cpuid.popcnt]
    test ecx, _CPUID_ECX_AES
    jz $+5H
    inc byte [esi+_cpuid.aes]
    test ecx, _CPUID_ECX_XSAVE
    jz $+5H
    inc byte [esi+_cpuid.xsave]
    test ecx, _CPUID_ECX_AVX
    jz $+5H
    inc byte [esi+_cpuid.avx]
    xor eax, eax
    mov al, _CPUID_LEAF_EXTEND_FEATURE
    cmp eax, edi
    ja _cpuid_detection_extended
    xor ecx, ecx
    mov cl, _CPUID_SUBLEAF_EXTEND_FEATURE
    cpuid
    test ebx, _CPUID_EBX_FSGSBASE
    jz $+5H
    inc byte [esi+_cpuid.fsgsbase]
    test ebx, _CPUID_EBX_BMI1
    jz $+5H
    inc byte [esi+_cpuid.bmi1]
    test ebx, _CPUID_EBX_SMEP
    jz $+5H
    inc byte [esi+_cpuid.smep]
    test ebx, _CPUID_EBX_BMI2
    jz $+5H
    inc byte [esi+_cpuid.bmi2]
    test ebx, _CPUID_EBX_RDSEED
    jz $+5H
    inc byte [esi+_cpuid.rdseed]
    test ebx, _CPUID_EBX_SMAP
    jz $+5H
    inc byte [esi+_cpuid.smap]
    test ebx, _CPUID_EBX_SHA
    jz $+5H
    inc byte [esi+_cpuid.sha]
    test ecx, _CPUID_ECX_UMIP
    jz $+5H
    inc byte [esi+_cpuid.umip]
    xor eax, eax
    mov al, _CPUID_LEAF_EXTEND_STATE
    cmp eax, edi
    ja _cpuid_detection_extended
    xor ecx, ecx
    mov cl, _CPUID_SUBLEAF_EXTEND_STATE
    cpuid
    test eax, _CPUID_EAX_XSAVES
    jz $+5H
    inc byte [esi+_cpuid.xsaves]
_cpuid_detection_extended:
    mov eax, _CPUID_LEAF_EXTEND_INFO
  assert (_CPUID_LEAF_EXTEND_INFO < _CPUID_LEAF_VIRTPHYSIZE)
    cmp eax, ebp
    ja _cpuid_detection_exit
    cpuid
    test edx, _CPUID_EDX_NX
    jz $+5H
    inc byte [esi+_cpuid.nx]
    mov eax, _CPUID_LEAF_VIRTPHYSIZE
    cmp eax, ebp
    ja _cpuid_detection_exit
    cpuid
    mov byte [esi+_cpuid.maxphyaddr], al
    clc
_cpuid_detection_exit:
    pop ebp edi edx ecx ebx
    ret

_bochs_override_msi_i440fx:
    mov eax, 080000070H
    mov edx, 000000CF8H
    out dx, eax
    mov eax, 00000004AH
    mov edx, 000000CFEH
    out dx, eax ; enable the SMM memory window (SMRCR)
    mov edi, (_BOCHS_SM_BASE + _SM_ENTRY_POINT)
    mov esi, _custom_smm
    mov ecx, (_custom_smm_end - _custom_smm)
    call _copy_string
    wbinvd
    mov eax, 080000070H
    mov edx, 000000CF8H
    out dx, eax
    mov eax, 00000000AH
    mov edx, 000000CFEH
    out dx, eax ; close the SMM memory window and enable normal SMM
    xor al, al
    out 0B2H, al
    jmp $
    hlt
_custom_smm:
use16
    nop
    mov eax, dword [_BOCHS_SM_BASE+_SM_ENTRY_POINT+07EFCH]
    add dword [_BOCHS_SM_BASE+_SM_ENTRY_POINT+07F78H], 2H ; lower RIP
    rsm
_custom_smm_end:
use32

_pci_access_configuration:
 ;  eax - pci bus
 ;  ebx - pci device
 ;  ecx - pci function
 ;  edx - pci offset (last 2H bit must be clear)
 ; out: cf - set if last 2H bit in edx not clear
 ; preserves: esi, edi, ebp
 ; note:
 ;  x86 processor implement two address space (IO,Memory).
 ;  PCI require an extra address space: configuration space.
    test dl, 011B
    stc
    jnz _pci_access_configuration_exit
    shl eax, _PCI_BUS_SHIFT
    and eax, _PCI_BUS_MASK
    shl ebx, _PCI_DEVICE_SHIFT
    and ebx, _PCI_DEVICE_MASK
    shl ecx, _PCI_FUNCTION_SHIFT
    and ecx, _PCI_FUNCTION_MASK
    or eax, ebx
    or eax, ecx
    lea eax, [_PCI_ENABLE+eax+edx]
    mov edx, _PCI_ADDRESS
    out dx, eax
_pci_access_configuration_exit:
    ret

_pci_read_configuration_space:
 ; in:
 ;  eax - pci bus
 ;  ebx - pci device
 ;  ecx - pci function
 ;  edx - pci offset (last 2H bit must be clear)
 ; out: cf - set if last 2H bit in edx not clear
 ; preserves: esi, edi, ebp
    call _pci_access_configuration
    jc _pci_read_configuration_space_exit
    mov edx, _PCI_DATA
    in eax, dx
_pci_read_configuration_space_exit:
    ret

_pci_write_configuration_space:
 ; in:
 ;  eax - pci bus
 ;  ebx - pci device
 ;  ecx - pci function
 ;  edx - pci offset (last 2H bit must be clear)
 ;  edi - data to write
 ; out: cf - set if last 2H bit in edx not clear
 ; preserves: esi, edi, ebp
    call _pci_access_configuration
    jc _pci_write_configuration_space_exit
    mov eax, edi
    mov edx, _PCI_DATA
    out dx, eax
_pci_write_configuration_space_exit:
    ret

_pci_read_configuration_header:
 ; in: 
 ;  eax - pci bus
 ;  ebx - pci device
 ;  ecx - pci function
 ;  esi - pci header address
 ; preserves: esi, edi, ebp
    push eax ebx ecx ebp
    xor ebp, ebp
  assert (_pci_configuration_header.sizeof)
_pci_read_configuration_header_loop:
    mov eax, dword [esp+00CH]
    mov ebx, dword [esp+8H]
    mov ecx, dword [esp+4H]
    mov edx, ebp
    call _pci_read_configuration_space
    mov dword [esi+ebp], eax
    add ebp, 4H
    cmp ebp, (_pci_configuration_header.sizeof shl 2H)
    jb _pci_read_configuration_header_loop
    pop ebp ecx ebx eax
    ret

_debug_force_reset:
 ; preserves: ebx, ecx, esi, edi, ebp
    xor eax, eax
    inc al
    mov edx, (_spurious_interrupt_gate or _SWAP_IDT_ASSIGN_GATE)
    call _set_and_swap_idt_vector
    mov edx, (_DR7 or _DR7_LE or _DR7_GE)
    mov dr7, edx
    mov edx, _DR6
    mov dr6, edx
    xor edx, edx
    mov dr0, edx
    mov dr1, edx
    mov dr2, edx
    mov dr3, edx
    jmp _swap_idt_vector

_debug_register_allocate:
 ; out:
 ;  al - target debug register [0H-3H]
 ;  cf - set if all debug register are reserved or GD is set in dr7
 ; preserves: ebx, ecx, edx, esi, edi, ebp
    push edx ebp
    call _debug_general_detect
    jc _debug_register_allocate_exit
    xor al, al
 rept 4H i:0H
 {
    test ebp, (_DR7_G#i or _DR7_L#i)
    jz _debug_register_allocate_exit
  if ((i) <> 3H)
    inc al
  end if
 }
    stc
_debug_register_allocate_exit:
    pop ebp edx
    ret

_debug_memory_range:
 ; in:
 ;  eax - kind of range
 ;  ebx - address to examine
 ;  ecx - range size (must not be greater than 4H)
 ; out: cf - set if argument are not valid
 ; preserves: esi, edi, ebp
    push esi edi ebp
    cmp eax, (4H + 1H)
    cmc
    jc _debug_memory_range_exit
    cmp al, _DEBUG_RW_INST_READ
    jnz _debug_memory_range_sanitize
    xor ecx, ecx
    inc cl
_debug_memory_range_sanitize:
    cmp ecx, (4H + 1H)
    cmc
    jc _debug_memory_range_exit
    xor edx, edx
    mov ebp, eax
_debug_memory_range_loop:
    jecxz _debug_memory_range_exit
    mov eax, ebx
    and al, (4H - 1H)
    mov al, byte [_debug_memory_range_align+eax]
    movzx edx, al
    cmp al, cl
    jbe _debug_memory_range_assign
    mov dl, 1H
    cmp cl, 2H
    jb _debug_memory_range_assign ; either 2H or 3H
    inc dl
_debug_memory_range_assign:
    call _debug_register_allocate
    jc _debug_memory_range_exit
    mov byte [_debug_memory_range_self], al
    shl byte [_debug_memory_range_self], 3H
    add byte [_debug_memory_range_self], (0C0H + _EBX)
    mov dr0, ebx
  label _debug_memory_range_self byte at ($ - 1H)
    add ebx, edx
    sub ecx, edx
    dec dl
    mov esi, dr7 ; call to _debug_register_allocate succeed so access to dr7 is safe
    or esi, dword [_debug_memory_range_activate+eax*4H]
    mov edi, ecx
 irp _kind*, length,rw
 {
    mov ecx, dword [_debug_memory_range_#_kind+eax*4H]
  match =rw, _kind \{ mov edx, ebp \}
    shl edx, cl
    or esi, edx
 }
    mov ecx, edi
    mov dr7, esi
    jmp _debug_memory_range_loop
_debug_memory_range_exit:
    pop ebp edi esi
    ret
_debug_memory_range_align:
    db 4H
    db 1H
    db 2H
    db 1H
_debug_memory_range_activate:
    dd (_DR7_G0 or _DR7_L0)
    dd (_DR7_G1 or _DR7_L1)
    dd (_DR7_G2 or _DR7_L2)
    dd (_DR7_G3 or _DR7_L3)
_debug_memory_range_length:
    dd _DR7_LEN0  
    dd _DR7_LEN1
    dd _DR7_LEN2
    dd _DR7_LEN3
_debug_memory_range_rw:
    dd _DR7_RW0
    dd _DR7_RW1
    dd _DR7_RW2
    dd _DR7_RW3

align 8H
_debug_general_detect_gate DT_gte _DE_PRESENT or _DPL0 or _386_INTERRUPT_GATE,\
        0H, _CODE_KERNEL, _debug_general_detect_trigger
_debug_general_detect:
 ; out:
 ;  eax = 1H (always)
 ;  ebp = dr7
 ;   cf - set when GD is set in dr7
 ; preserves: ebx, ecx, esi, edi
    xor eax, eax
    inc al
    mov edx, (_debug_general_detect_gate or _SWAP_IDT_ASSIGN_GATE)
    call _set_and_swap_idt_vector
    mov ebp, dr7
_debug_general_detect_exit:
    call _swap_idt_vector
    test ebp, _DR7_GD
    jmp _invert_zero_carry
_debug_general_detect_trigger:
    mov ebp, dr7
    or ebp, _DR7_GD
    mov dr7, ebp
    mov dword [esp+_IRET_EIP], _debug_general_detect_exit
    iretd

_debug_save_register:
 ; in: ebx - target process pointer
 ; out: cf - save not performed
 ; preserves: ebx, ecx, esi, edi
    cmp byte [ebx+_process.dbgctx.active], 0H
    stc
    jz _debug_save_register_exit
    call _debug_general_detect
    jc _debug_save_register_exit
 irp _kind*, dr0,dr1,dr2,dr3,dr6,dr7
 {
    mov eax, _kind
    mov dword [ebx+_process.dbgctx.#_kind], eax
 }
_debug_save_register_exit:
    ret

_debug_export_register:
 ; in: ebx - target process pointer
 ; preserves: ebx, ecx, esi, edi, ebp
    call _debug_force_reset
    cmp byte [ebx+_process.dbgctx.active], 0H
    jz _debug_export_register_exit
 irp _kind*, dr0,dr1,dr2,dr3,dr6,dr7
 {
    mov eax, dword [ebx+_process.dbgctx.#_kind]
    mov _kind, eax
 }
_debug_export_register_exit:
    ret

include "apic.inc"

_identify_io_apic:
 ; in: ebx - mp entry object pointer
    movzx esi, byte [ebx+_io_apic_entry.io_apic_flags]
    test esi, _IO_APIC_FLAGS_EN
    jz _identify_io_apic_exit
    inc byte [_io_apic_count]
    cmp byte [_io_apic_count], 1H
    jnz _identify_io_apic_exit
    lea esi, [ebx+_io_apic_entry.io_apic_address]
    mov edi, _io_apic_base
    movsd
_identify_io_apic_exit:
    ret

_count_processor:
    inc byte [_processor_count]
    ret

_set_io_apic_irq_pin:
 ; in:
 ;  edi - destination register
 ;  ebp - current rt index
    push eax
    lea eax, [_REDIRECTION_TABLE_BASE+ebp*2H+1H]
    mov byte [_PAE_IO_APIC+_INDEX_REGISTER], al
    mov dword [_PAE_IO_APIC+_DATA_REGISTER], edi
    dec al
    mov byte [_PAE_IO_APIC+_INDEX_REGISTER], al
    lea eax, [ebp+_INTEL_RESERVED_INT]
    movzx esi, byte [ebx+_io_interrupt_entry.interrupt_type]
    ;cmp esi, ((_set_io_apic_irq_pin_table_end - _set_io_apic_irq_pin_table) shr 2H)
    ;jae
    or eax, dword [_set_io_apic_irq_pin_table+esi*4H]
    movzx esi, word [ebx+_io_interrupt_entry.io_interrupt_flags]
    and esi, _INTERRUPT_EL_MASK
    shr esi, _INTERRUPT_EL_SHIFT    
    cmp esi, _INTERRUPT_EL_LEVEL
    jnz _set_io_apic_irq_pin_assign
    or eax, _APIC_LEVEL_TRIGGER
    movzx esi, word [ebx+_io_interrupt_entry.io_interrupt_flags]
    and esi, _INTERRUPT_PO_MASK
    shr esi, _INTERRUPT_PO_SHIFT
    cmp esi, _INTERRUPT_PO_HIGH
    jz _set_io_apic_irq_pin_assign
    or eax, _APIC_POLARITY_LOW
_set_io_apic_irq_pin_assign:
    mov dword [_PAE_IO_APIC+_DATA_REGISTER], eax
    inc ebp
    pop eax
    ret
_set_io_apic_irq_pin_table:
    dd _APIC_DELIVERY_FIXED
    dd _APIC_DELIVERY_NMI
    dd _APIC_DELIVERY_SMI
    dd _APIC_DELIVERY_EXTINT
_set_io_apic_irq_pin_table_end:

_extract_primary_apic_information _mp_predicate _count_processor, _nothing, _identify_io_apic, _nothing, _nothing
_configure_io_apic_rt _mp_predicate _nothing, _nothing, _nothing, _set_io_apic_irq_pin, _nothing

_parse_mp_conftable_entry:
 ; in:
 ;  eax - mp predicate object pointer
 ;  esi - parameter passed as-in
 ;  edi - parameter passed as-in
 ;  ebp - parameter passed as-in
 ; out: cf - set if no entry found or MP base address is unknown
 ; preserves: esi, edi, ebp
 ; note: predicate in _mp_predicate must not visibly modify a register except esi,edi,ebp
    push esi edi ebp
    cmp dword [_mp_floating_pointer_found], 1H
    jz _parse_mp_conftable_entry_exit
    mov ebx, dword [_mp_floating_pointer_base]
    mov ebx, dword [ebx+_mp_floating_pointer.physical_address]
    mov ecx, dword [ebx+_mp_configuration_table.entry_count]
    jecxz _parse_mp_conftable_entry_exit
    add ebx, _mp_configuration_table.sizeof
_parse_mp_conftable_entry_iterate:
    movzx edx, byte [ebx]
    cmp dl, (_LOCAL_INTERRUPT_ENTRY - _PROCESSOR_ENTRY)
    jae _parse_mp_conftable_entry_exit
    shl dl, 2H
    call dword [eax+edx]
    add ebx, dword [_parse_mp_conftable_entry_table+edx]
    loop _parse_mp_conftable_entry_iterate
    clc
    jmp _parse_mp_conftable_entry_exit+1H
_parse_mp_conftable_entry_exit:
    stc
    pop ebp edi esi
    ret
_parse_mp_conftable_entry_table:
    dd _processor_entry.sizeof 
    dd _bus_entry.sizeof
    dd _io_apic_entry.sizeof
    dd _io_interrupt_entry.sizeof
    dd _local_interrupt_entry.sizeof
_parse_mp_conftable_entry_table_end:

_gp_intercept DT_gte _DE_PRESENT or _DPL0 or _386_INTERRUPT_GATE, 0H, _CODE_KERNEL, _msr_not_defined
_gp_save: dq 0H
_msr_defined: db 0H
_msr_not_defined:
    not byte [_msr_defined]
    add esp, 4H
    add dword [esp+_IRET_EIP], 2H
    iretd

_try_access_msr:
 ; in:
 ;  eax - low part MSR (in case of wrmsr)
 ;  edx - high part MSR (in case of wrmsr)
 ;  ecx - MSR address
 ;  ebx - instruction (rdmsr, wrmsr) to execute
 ; out: cf - set if #GP has been raised
 ; preserves: ecx, esi, edi, ebp
 ; note: try to call this function as a last ressort, when you can't be sure of the existence of an MSR
    push esi edi
    cmp ebx, _RDMSR
    jz _try_access_msr_self
    cmp ebx, _WRMSR
    stc
    jnz _try_access_msr_exit
_try_access_msr_self:
    mov word [_try_access_msr_execute], bx
    mov byte [_msr_defined], (not 0H)
    mov ebx, (_IDT + _vector_13)
    mov esi, ebx
    mov edi, _gp_save
 rept 2H { movsd }
    mov esi, _gp_intercept
    mov edi, ebx
 rept 2H { movsd }
_try_access_msr_execute:
    dw 0H
    mov esi, _gp_save
    mov edi, ebx
 rept 2H { movsd }
    cmp byte [_msr_defined], (not 0H)
_try_access_msr_exit:
    pop edi esi
    ret

_write_msr:
 ; in:
 ;  eax - low part MSR
 ;  edx - high part MSR
 ;  ecx - MSR address
 ; preserves: eax, edx, ecx, esi, edi, ebp
 ; note: This function does not generate a #GP when the address is not known to the target core
    mov ebx, _WRMSR
    jmp _try_access_msr

_read_msr:
 ; in: ecx - MSR address
 ; out:
 ;  eax - low part MSR
 ;  edx - high part MSR
 ; preserves: ecx, edi, edi, ebp
 ; note: This function does not generate a #GP when the address is not known to the target core
    mov ebx, _RDMSR
    jmp _try_access_msr

_allocate_variable_mtrr:
 ; out:
 ;  ebx - MTRR mask (if found)
 ;  ecx - MTRR physical base (if found)
 ;  edx - 0H if cf not set
 ;   cf - set if not found
 ; preserves: esi, edi, ebp
    push ebp
    mov ebx, _allocate_variable_mtrr_table
    movzx ecx, byte [_singleton.varmtrr]
    cmp cl, ((_allocate_variable_mtrr_table_end - _allocate_variable_mtrr_table) shr 3H)
    jbe _allocate_variable_mtrr_loop
    mov cl, _MTRR_PENTIUM
_allocate_variable_mtrr_loop:
    jecxz _allocate_variable_mtrr_carry
    mov ebp, ecx
    mov ecx, dword [ebx+4H]
    rdmsr
    xor edx, edx
    test eax, _MTRR_PHYS_MASK_V
    jnz _allocate_variable_mtrr_update
    mov ebx, dword [ebx]
    xchg ebx, ecx
    jmp _allocate_variable_mtrr_carry+1H
_allocate_variable_mtrr_update:
    lea ecx, [ebp-1H]   
    add ebx, 8H
    jmp _allocate_variable_mtrr_loop
_allocate_variable_mtrr_carry:
    stc
    pop ebp
    ret
_allocate_variable_mtrr_table:
    dd _MTRR_PHYS_BASE_0, _MTRR_PHYS_MASK_0
    dd _MTRR_PHYS_BASE_1, _MTRR_PHYS_MASK_1
    dd _MTRR_PHYS_BASE_2, _MTRR_PHYS_MASK_2
    dd _MTRR_PHYS_BASE_3, _MTRR_PHYS_MASK_3
    dd _MTRR_PHYS_BASE_4, _MTRR_PHYS_MASK_4
    dd _MTRR_PHYS_BASE_5, _MTRR_PHYS_MASK_5
    dd _MTRR_PHYS_BASE_6, _MTRR_PHYS_MASK_6
    dd _MTRR_PHYS_BASE_7, _MTRR_PHYS_MASK_7
_allocate_variable_mtrr_table_end:

_allocate_and_mark_memory_range_mtrr:
    mov eax, _allocate_variable_mtrr
_mark_memory_range_mtrr:
 ; in:
 ;  eax - predicate to call to obtain new set of MSR
 ;  ebx - start physical location
 ;  ecx - size range
 ;  edx - memory type
 ; out:
 ;  ebx - MTRR mask (if found)
 ;  ecx - MTRR physical base (if found)
 ;   cf - set if error has occured
 ; preserves: esi, edi, ebp
    push esi edi
    bsr ecx, ecx
    jz _mark_memory_range_mtrr_exit
    cmp ecx, _PAGE_TABLE_SHIFT
    jc _mark_memory_range_mtrr_exit+1H
    cmp dl, 2H
    jz _mark_memory_range_mtrr_exit
    cmp dl, 3H
    jz _mark_memory_range_mtrr_exit
    cmp edx, _MTRR_TYPE_WB
    ja _mark_memory_range_mtrr_exit
    mov esi, ebx
    or esi, edx
    xor edx, edx
    inc dl
    shl edx, cl
    dec edx
    not edx
    lea edi, [edx+_MTRR_PHYS_MASK_V]
    xor edx, edx
    call eax
    jc _mark_memory_range_mtrr_exit+1H
    mov eax, esi
    wrmsr
    mov edx, ecx
    call _maxphyaddr_high_mask
    mov ecx, ebx
    mov ebx, edx
    mov edx, eax
    mov eax, edi
    wrmsr
    xchg ebx, ecx
    jmp _mark_memory_range_mtrr_exit+1H
_mark_memory_range_mtrr_exit:
    stc
    pop edi esi
    ret

enum _SENSITIVE_TEMPORARY, _SENSITIVE_RECURSIVE
_sensitive_linear:
 ; in:
 ;  eax - kind to check
 ;  ebx - linear address
 ; out: cf - set if it's a greater (>=) than linear sensitive threshold (temporary, recursive)
 ; preserves: eax, ebx, ecx, edx, esi, edi, ebp
    cmp eax, _SENSITIVE_RECURSIVE
    ja _sensitive_linear_carry
    test byte [_singleton.pae], 1H
    jnz _sensitive_linear_temporary_pae
    cmp ebx, _SENSITIVE_TEMPORARY_START
    jmp _sensitive_linear_next_1
_sensitive_linear_temporary_pae:
    cmp ebx, _PAE_SENSITIVE_TEMPORARY_START
_sensitive_linear_next_1:
    cmc
    jnc _sensitive_linear_exit
    test al, _SENSITIVE_RECURSIVE
    jz _sensitive_linear_carry
    test byte [_singleton.pae], 1H
    cmp ebx, _SENSITIVE_RECURSIVE_START
    jmp _sensitive_linear_next_2
_sensitive_linear_recursive_pae:
    cmp ebx, _PAE_SENSITIVE_RECURSIVE_START
_sensitive_linear_next_2:
    cmc
    jmp _sensitive_linear_exit
_sensitive_linear_carry:
    stc
_sensitive_linear_exit:
    ret

_ensure_flags_exclusive:
 ; in: 
 ;  eax - flags
 ;  ebx - flags to test for exclusiveness
 ; out: cf - set if multiple flags set or zero one
 ; preserves: eax, edx, esi, edi, ebp
    and ebx, eax
    stc
    jz _ensure_flags_exclusive_exit
    bsf ecx, ebx
    bsr ebx, ebx
    cmp ebx, ecx
    jz _ensure_flags_exclusive_exit
    stc
_ensure_flags_exclusive_exit:
    ret

_ITERATE_REMAIN = (_PUSHA_TOTAL + (8H shl 2H))
enum & _ITERATE_PDPTE, _ITERATE_PDE, _ITERATE_PTE, _ITERATE_REVERSE_COUNTER, _ITERATE_CARRY_ERROR
_iterate_range_linear:
 ; in:
 ;  eax - functor to call of each item
 ;  ebx - current (recursive) linear address passed to the functor
 ;  ecx - argument count of current entry passed to the functor
 ;  edx - iterate range flags
 ;  esi - min virtual address
 ;  edi - max virtual address
 ;  ebp - argument passed as-in to the functor
 ; out:
 ;  al - 0FFH if the functor returned with carry, 0H otherwise
 ;  cf - set on error
 ; preserves: ebx, ecx, edx, esi, edi, ebp
 ; note: take advantage of the recursive linear fact for iterating over the (PDPTE/PDE/PTE) as fast as possible
    push ebx ecx esi edi ebp
    push 0H ; temporary sensitive linear
    mov ebp, eax
    mov ebx, (_ITERATE_PDPTE or _ITERATE_PDE or _ITERATE_PTE or _ITERATE_REVERSE_COUNTER or _ITERATE_CARRY_ERROR)
    cmp edx, ebx
    ja _iterate_range_linear_carry
    xor bl, (_ITERATE_REVERSE_COUNTER or _ITERATE_CARRY_ERROR)
    mov eax, edx
    call _ensure_flags_exclusive
    jc _iterate_range_linear_carry+1H
    mov eax, _SENSITIVE_RECURSIVE
    lea ebx, [edi-1H]
    call _sensitive_linear
    jc _iterate_range_linear_carry+1H
    mov al, _SENSITIVE_TEMPORARY
    mov ebx, esi
    call _sensitive_linear
    salc
    mov byte [esp], al
    test dl, _ITERATE_PDPTE
    jz _iterate_range_linear_next
    test al, al
    js _iterate_range_linear_carry
    test byte [_singleton.pae], 1H
    jz _iterate_range_linear_carry
    mov ecx, (_iterate_range_make_table + 00CH)
    jmp _iterate_range_linear_transform
_iterate_range_linear_next:
    test dl, _ITERATE_PDE
    mov ecx, (_iterate_range_make_table + 8H)
    jnz _iterate_range_linear_sanitize
    mov ecx, (_iterate_range_make_table + 4H)
_iterate_range_linear_sanitize:
    test al, al
    jns _iterate_range_linear_transform
    test dl, _ITERATE_PDE
    mov ecx, (_iterate_range_make_table + 4H)
    jnz _iterate_range_linear_transform
    mov ecx, _iterate_range_make_table
_iterate_range_linear_transform:
    cmp edi, esi
    jbe _iterate_range_linear_carry
    mov ebx, esi
    call dword [ecx]
    mov esi, ebx
    mov ebx, edi
    call dword [ecx]
    xchg edi, ebx
    mov al, byte [esp]
    test al, al
    jns _iterate_range_linear_align
    cmp ecx, _iterate_range_make_table
    jz _iterate_range_linear_counter
    jmp _iterate_range_linear_invoke
_iterate_range_linear_align:
    cmp ecx, (_iterate_range_make_table + 4H)
    jz _iterate_range_linear_counter
_iterate_range_linear_invoke:
    call dword [ecx-4H]
    and ebx, _PAGE_OFFSET_MASK
    jz _iterate_range_linear_counter
    call _skip_entry_edi
_iterate_range_linear_counter:
    mov eax, ebp
    xor ecx, ecx
    inc cl
    mov ebp, dword [esp+4H]
    test dl, _ITERATE_REVERSE_COUNTER
    jz _iterate_range_linear_check
    mov ecx, edi
    sub ecx, esi
    shr ecx, 2H
    test byte [_singleton.pae], 1H
    jz _iterate_range_linear_check
    shr ecx, 1H
    jmp _iterate_range_linear_check
_iterate_range_linear_loop:
    mov ebx, esi
    pusha
    call eax
    popa
    jnc _iterate_range_linear_skip
    salc
    test dl, _ITERATE_CARRY_ERROR
    jnz _iterate_range_linear_carry
    jmp _iterate_range_linear_exit+1H
_iterate_range_linear_skip:
    call _skip_entry_esi
    test dl, _ITERATE_REVERSE_COUNTER
    jz _iterate_range_linear_update
    dec ecx
    jmp _iterate_range_linear_check
_iterate_range_linear_update:
    inc ecx
_iterate_range_linear_check:
    cmp esi, edi
    jb _iterate_range_linear_loop
    xor al, al
_iterate_range_linear_exit:
    clc
    jmp _iterate_range_linear_carry+1H
_iterate_range_linear_carry:
    stc
    lea esp, [esp+4H]
    pop ebp edi esi ecx ebx 
    ret
_iterate_range_make_table:
    dd _linear_make_no_recursive
    dd _linear_make_single_recursive
    dd _linear_make_double_recursive
    dd _linear_make_triple_recursive

_available_linear_range:
 ; in:
 ;   al - aligned on page-directory basis (for PSE)
 ;  ecx - count of page wanted to be installed
 ;  esi - min virtual address
 ;  edi - max virtual address
 ; out:
 ;  ebx - start of linear address where the range reside
 ;  esi = ebx
 ;  edi - end of the target linear range
 ;   cf - set on error or no match found
 ; preserves: edx, ebp
    push edx ebp
    stc
    jecxz _available_linear_range_exit
    test al, al
    setnz al
    mov ebp, ecx
    push 0H  ; when range found, start linear
    push eax ; align on page directory (PSE)
    push eax ; must skip, relevant only with align
    push 0H  ; counter of free
    mov eax, edi
    sub eax, esi
    cmp eax, ebp
    jc _available_linear_range_exit
    mov eax, _available_linear_range_iterate
    mov edx, (_ITERATE_PTE or _ITERATE_REVERSE_COUNTER)
    call _iterate_range_linear
    jc _available_linear_range_exit
    test al, al
    stc
    jz _available_linear_range_exit
    cmp dword [esp], ebp
    stc
    jnz _available_linear_range_exit 
    mov ebx, dword [esp+00CH]
    call _linear_make_no_recursive
    shl ebp, _PAGE_TABLE_SHIFT
    mov esi, ebx
    lea edi, [ebx+ebp]
_available_linear_range_exit:
    lea esp, [esp+010H]
    pop ebp edx
    ret
_available_linear_range_iterate:
    test byte [esp+_ITERATE_REMAIN+4H], 1H
    jz _available_linear_range_iterate_continue
    mov eax, ebx
    and eax, _PAGE_OFFSET_MASK
    test eax, eax
    jnz _available_linear_range_iterate_exit
    mov byte [esp+_ITERATE_REMAIN+4H], 0H
_available_linear_range_iterate_continue:
    call _page_present
    jnc _available_linear_range_iterate_reset
    cmp dword [esp+_ITERATE_REMAIN], 0H
    jnz _available_linear_range_iterate_increment
    mov dword [esp+_ITERATE_REMAIN+00CH], ebx
_available_linear_range_iterate_increment:
    inc dword [esp+_ITERATE_REMAIN]
    cmp dword [esp+_ITERATE_REMAIN], ebp
    cmc
    jmp _available_linear_range_iterate_exit
_available_linear_range_iterate_reset:
    cmp ecx, ebp
    jc _available_linear_range_iterate_exit
    mov dword [esp+_ITERATE_REMAIN], 0H
    test byte [esp+_ITERATE_REMAIN+8H], 1H
    jz _available_linear_range_iterate_exit
    mov byte [esp+_ITERATE_REMAIN+4H], 1H
_available_linear_range_iterate_exit:
    ret

_count_free_entry_range:
 ; in:
 ;  esi - min virtual address
 ;  edi - max virtual address
 ; out: eax - count if free (PDPTE/PDE/PTE) in the range esi:edi
 ; preserves: ebx, ecx, esi, edi, ebp
    push 0H ; count of PDPTE
    push 0H ; count of PDE
    push 0H ; count of PTE
    test byte [_singleton.pae], 1H
    jz _count_free_entry_range_perform
    mov eax, _count_free_entry_range_pdpte
    mov edx, _ITERATE_PDPTE
    call _iterate_range_linear
    jc _count_free_entry_range_exit
_count_free_entry_range_perform:
    mov eax, _count_free_entry_range_pde
    mov edx, _ITERATE_PDE
    call _iterate_range_linear
    jc _count_free_entry_range_exit
    mov eax, _count_free_entry_range_pte
    mov edx, _ITERATE_PTE
    call _iterate_range_linear
    jc _count_free_entry_range_exit
    xor eax, eax
    add eax, dword [esp]
    add eax, dword [esp+4H]
    add eax, dword [esp+8H]
    clc
_count_free_entry_range_exit:
    lea esp, [esp+00CH]
    ret
_count_free_entry_range_pdpte:
    test byte [ebx], _PE_PRESENT
    jnz _count_free_entry_range_pdpte_exit
    inc dword [esp+_ITERATE_REMAIN+8H]
_count_free_entry_range_pdpte_exit:
    ret
_count_free_entry_range_pde:
    mov edx, ebx
    test byte [_singleton.pae], 1H
    jz _count_free_entry_range_pde_simple
    call _linear_make_triple_recursive
    test byte [ebx], _PE_PRESENT
    jz _count_free_entry_range_pde_update
_count_free_entry_range_pde_simple:
    test byte [edx], _PE_PRESENT
    jnz _count_free_entry_range_pde_exit
_count_free_entry_range_pde_update:
    inc dword [esp+_ITERATE_REMAIN+4H]
_count_free_entry_range_pde_exit:
    ret
_count_free_entry_range_pte:
    mov edx, ebx
    test byte [_singleton.pae], 1H
    jz _count_free_entry_range_pte_simple
    call _linear_make_triple_recursive
    test byte [ebx], _PE_PRESENT
    jz _count_free_entry_range_pte_update
_count_free_entry_range_pte_simple:
    mov ebx, edx
    call _linear_make_double_recursive
    test byte [ebx], _PE_PRESENT
    jz _count_free_entry_range_pte_update
    test byte [ebx], _PDE_SIZE
    jnz _count_free_entry_range_pte_exit
    test byte [edx], _PE_PRESENT
    jnz _count_free_entry_range_pte_exit
_count_free_entry_range_pte_update:
    inc dword [esp+_ITERATE_REMAIN]
_count_free_entry_range_pte_exit:
    ret

_not_present_predicate:
    test dword [ebx], _PE_PRESENT
    jmp _convert_zero_carry

_not_present_pae_predicate:
    ; XXX
    ret

_present_predicate:
    call _not_present_predicate
    cmc
    ret

_free_entry_predicate:
    cmp dword [ebx], 0H
    jmp _convert_zero_carry

_free_entry_pae_predicate:
    cmp dword [ebx], 0H
    jnz $+6H
    cmp dword [ebx+4H], 0H
    jmp _convert_zero_carry

_swap_entry_predicate:
    call _not_present_predicate
    jnc $+7H
    call _free_entry_predicate
    ret

_store_wp_entry:
    push eax
    or al, (_PE_READ_WRITE or _PE_PRESENT)
    call _store_entry
    pop eax
    ret

_store_entry:
 ; in: 
 ;  eax - store this entry at [edi] 
 ;  edx - store this entry at [edi+4H] (onyl if PAE)
 ;  edi - entry index 
 ; preserves: eax, ebx, ecx, edx, esi, ebp
    stosd
    ;test byte [_singleton.pae], 1H
    ;jz _store_entry_exit
    push eax
    mov eax, edx
    stosd
    pop eax
_store_entry_exit:
    ret

_clear_entry:
    xor eax, eax
    xor edx, edx
    jmp _store_entry

_load_entry:
 ; in: esi - entry index
 ; out:
 ;  eax - load the entry at [esi]
 ;  edx - load the entry at [esi+4H] (only if PAE, zero out otherwise) 
 ;  esi - entry index
 ; preserves: ebx, ecx, edx, edi, ebp
    lodsd
    xor edx, edx
    test byte [_singleton.pae], 1H
    jz _load_entry_exit
    mov edx, eax
    lodsd
    xchg eax, edx
_load_entry_exit:
    ret

irp _kind*, esi,edi
{
_skip_entry_#_kind:
    add _kind, 4H
    test byte [_singleton.pae], 1H
    jz $+5H
    add _kind, 4H
    ret
}

_copy_wp_entry:
    call _load_entry
    jmp _store_wp_entry

_copy_entry:
    call _load_entry
    jmp _store_entry
    
_PDPTE_RESERVED_BIT = ((not _PAGE_OFFSET_MASK) or _PE_PCD or _PE_PWT or _PE_PRESENT)
_pdpt_reserved_current:
    mov ebx, _PAE_PDPT_RECURSIVE_VIRTUAL
_pdpt_reserved:
 ; in: ebx - pdpt table pointer
 ; preserves: eax, ebx, ecx, edx, edi, esi, ebp
    test byte [_singleton.pae], 1H
    jz _pdpt_reserved_exit
    and dword [ebx+000H], _PDPTE_RESERVED_BIT
    and dword [ebx+008H], _PDPTE_RESERVED_BIT
    and dword [ebx+010H], _PDPTE_RESERVED_BIT
    and dword [ebx+018H], _PDPTE_RESERVED_BIT
_pdpt_reserved_exit:
    ret

_pdpt_read_write_current:
    mov ebx, _PAE_PDPT_RECURSIVE_VIRTUAL
_pdpt_read_write:
 ; in: ebx - pdpt table pointer
 ; preserves: eax, ebx, ecx, edx, edi, esi, ebp
 ; note: useful when write protect enable, update only when _PA_PRESENT is active too
    test byte [_singleton.pae], 1H
    jz _pdpt_read_write_exit
 rept 4H i:0H
 {
    test byte [ebx+(i*8H)], _PE_PRESENT
    jz _pdpt_read_write_#i
    or byte [ebx+(i*8H)], _PE_READ_WRITE
_pdpt_read_write_#i:
 }
_pdpt_read_write_exit:
    ret

_refresh_pae_pdptr:
 ; out: cf - always clear
 ; preserves: ecx, edx, edi, esi, ebp
 ; note: reload of PDPTE internal register (PDPTE0, PDPTE1, PDPTE2, PDPTE3)
    test byte [_singleton.pae], 1H
    jz _refresh_pae_pdptr_exit
    call _pdpt_reserved_current
    mov ebx, cr0
    mov eax, ebx
    test eax, _CR0_NW
    jz _refresh_pae_pdptr_disable
    xor eax, _CR0_NW
    jmp _refresh_pae_pdptr_update
_refresh_pae_pdptr_disable:
    xor eax, _CR0_CD
_refresh_pae_pdptr_update:
    mov cr0, eax
    mov cr0, ebx
    call _pdpt_read_write_current
_refresh_pae_pdptr_exit:
    ret

_convert_pse_page:
 ; in: ecx - convert PSE page value to the count of 4K page
 ; out:
 ;  ecx - total page in PSE page
 ;   cf - set if the number of page does not fit into ecx or PSE is not present on the CPU
 ; preserves: eax, ebx, edx, esi, edi, ebp
 ; note: ecx is not changed is PSE is not present on the system
    test byte [_singleton.pse], 1H
    stc
    jz _convert_pse_page_exit
    cmp ecx, (100000000H shr (bsf _PAE_TABLE_ENTRY_COUNT))
    cmc
    jc _convert_pse_page_exit
    shl ecx, (bsf _PAE_TABLE_ENTRY_COUNT)
    test byte [_singleton.pae], 1H
    jnz _convert_pse_page_exit
    shl ecx, ((bsf _TABLE_ENTRY_COUNT) - (bsf _PAE_TABLE_ENTRY_COUNT)) ; carry set if overflow
_convert_pse_page_exit:
    ret

enum & _ALLOCATION_VIRTUAL, _ALLOCATION_PSE, _ALLOCATION_HINT, _ALLOCATION_HOLE
_min_virtual_address: dd _PAGE_FRAME_SIZE ; don't apply to _ALLOCATION_PHYSICAL only _ALLOCATION_VIRTUAL
_map_one_page_virtual_address:
    xor ecx, ecx
    inc cl
_map_virtual_address:
 ; in:
 ;  eax - kind of allocation
 ;  ebx - hint of address to use, only when eax = _ALLOCATION_VIRTUAL
 ;  ecx - count of page to install (if _ALLOCATION_HINT = 1H), only when eax = _ALLOCATION_VIRTUAL
 ;  edx - _allocation_functors object pointer, only when eax = _ALLOCATION_VIRTUAL, otherwise a function pointer
 ;  esi - min virtual address (if _ALLOCATION_HINT = 1H), only when eax = _ALLOCATION_VIRTUAL
 ;  edi - max virtual address (if _ALLOCATION_HINT = 1H), only when eax = _ALLOCATION_VIRTUAL
 ; out:
 ;  ebx - resulting address
 ;   cf - set when no virtual range has been found for this address or out of memory
 ; preserves: eax, ecx, ebp
 ; note:
 ;  Only kernel in kernel virtual mode can call _map_virtual_address with _ALLOCATION_PHYSICAL
 ;  _ALLOCATION_PHYSICAL return address as-in and resulting page must always be in supervisor state
 ;  _ALLOCATION_PSE *must* be used when a predicate (ecx) that return _PDE_SIZE in the flag to function properly
    push ebp ecx eax
    mov ebp, edx
    cmp eax, (_ALLOCATION_VIRTUAL or _ALLOCATION_PSE or _ALLOCATION_HINT or _ALLOCATION_HOLE)
    ja _map_virtual_address_carry
    test al, _ALLOCATION_VIRTUAL
    jz _map_virtual_address_physical
    test al, _ALLOCATION_PSE
    jz _map_virtual_address_virtual
    cmp dword [ebp+_allocation_functors.pte], 0H
    jnz _map_virtual_address_carry
    call _convert_pse_page
    jc _map_virtual_address_exit
    jmp _map_virtual_address_virtual
_map_virtual_address_physical:
    call edx
    jc _map_virtual_address_exit
    mov ebx, eax
    and ebx, (not _PAGE_OFFSET_MASK)
    mov esi, ebx
    mov edx, ecx
    shl edx, _PAGE_TABLE_SHIFT
    add esi, edx
    jc _map_virtual_address_exit
    cmp esi, _KERNEL_VIRTUAL
    cmc
    jnc _map_virtual_address_exit
_map_virtual_address_overlap:
    call _deallocate_pages
    jmp _map_virtual_address_exit
_map_virtual_address_virtual:
    test al, _ALLOCATION_HINT
    jz _map_virtual_address_range
    test ecx, ecx
    jz _map_virtual_address_carry
    mov esi, ebx
    mov edx, ecx
    shl edx, _PAGE_TABLE_SHIFT
    lea edi, [esi+edx]
_map_virtual_address_range:
    test al, _ALLOCATION_PSE
    jz _map_virtual_address_sanitize
    _align_up edi, _PAE_PSE_PAGE_FRAME_SIZE
    mov ebx, esi
    and ebx, _PAE_PSE_OFFSET_MASK
    jnz _map_virtual_address_carry
    test byte [_singleton.pae], 1H
    jnz _map_virtual_address_sanitize
    test esi, (1H shl _PAE_PAGE_DIRECTORY_SHIFT)
    jnz _map_virtual_address_carry
    _align_up edi, _PSE_PAGE_FRAME_SIZE
_map_virtual_address_sanitize:
    call _map_virtual_address_bound
    jc _map_virtual_address_exit
    mov ebx, esi
    test al, _ALLOCATION_HOLE
    jnz _map_virtual_address_count
    test al, _ALLOCATION_PSE
    setnz al
    call _available_linear_range
    jc _map_virtual_address_exit
_map_virtual_address_count:
    call _count_free_entry_range
    jc _map_virtual_address_exit
    cmp eax, dword [_frame.free]
    ja _map_virtual_address_carry
    test byte [_singleton.pae], 1H
    jz _map_virtual_address_perform
    mov eax, _map_virtual_address_iterate_pdpte
    mov edx, _ITERATE_PDPTE
    call _iterate_range_linear
    jc _map_virtual_address_exit
_map_virtual_address_perform:
    mov eax, _map_virtual_address_iterate_pde
    mov edx, _ITERATE_PDE
    call _iterate_range_linear
    jc _map_virtual_address_exit
    test byte [esp], _ALLOCATION_PSE
    jnz _map_virtual_address_exit
    mov eax, _map_virtual_address_iterate_pte
    mov edx, _ITERATE_PTE
    call _iterate_range_linear
    jmp _map_virtual_address_exit
_map_virtual_address_carry:
    stc
_map_virtual_address_exit:
    pop eax ecx ebp
    ret

_map_virtual_address_iterate_pdpte:
    test byte [ebx], _PE_PRESENT
    jnz _map_virtual_address_iterate_pdpte_exit
    call dword [ebp+_allocation_functors.pdpte]
    jc _map_virtual_address_iterate_pdpte_exit
    mov ebp, ebx
    call _pdpt_read_write_current
    mov ebx, ebp
    and ebx, _PAGE_OFFSET_MASK
    add ebx, _PAE_PTE_RECURSIVE_BASE_ITSELF
    and al, (not _PDE_SIZE)
    or al, _PE_READ_WRITE 
    and edx, (not _PAE_FLAGS_UPPER_MASK)
    mov dword [ebx], eax
    mov dword [ebx+4H], edx
    mov ebx, ebp
    and eax, _PDPTE_RESERVED_BIT
    mov dword [ebx], eax
    mov dword [ebx+4H], edx
    call _refresh_pae_pdptr
_map_virtual_address_iterate_pdpte_exit:
    ret

_map_virtual_address_iterate_pde:
    test byte [ebx], _PE_PRESENT
    jz _map_virtual_address_iterate_pde_invoke
    test byte [esp+_ITERATE_REMAIN], _ALLOCATION_PSE
    jz _map_virtual_address_iterate_pde_exit
    mov esi, ebx
    call _load_entry
    call _deallocate_page
    jc _map_virtual_address_iterate_pde_exit
_map_virtual_address_iterate_pde_invoke:
    call dword [ebp+_allocation_functors.pde]
    jc _map_virtual_address_iterate_pde_exit
    or al, _PE_READ_WRITE 
    test byte [esp+_ITERATE_REMAIN], _ALLOCATION_PSE
    jz _map_virtual_address_iterate_pde_execute
    or al, _PDE_SIZE
    jmp _map_virtual_address_iterate_pde_store
_map_virtual_address_iterate_pde_execute:
    and edx, (not _PAE_FLAGS_UPPER_MASK)
_map_virtual_address_iterate_pde_store:
    mov edi, ebx
    call _store_entry
_map_virtual_address_iterate_pde_exit:
    ret

_map_virtual_address_iterate_pte:
    test byte [ebx], _PE_PRESENT
    jnz _map_virtual_address_iterate_pte_present
    call dword [ebp+_allocation_functors.pte]
    jc _map_virtual_address_iterate_pte_exit
    mov edi, ebx
    call _store_entry
    jmp _map_virtual_address_iterate_pte_exit
_map_virtual_address_iterate_pte_present:
    test byte [esp+_ITERATE_REMAIN], _ALLOCATION_HOLE
    jnz _map_virtual_address_iterate_pte_exit
    stc
_map_virtual_address_iterate_pte_exit:
    ret

_map_virtual_address_bound:
 ; in:
 ;  esi - min virtual range
 ;  esi - max virtual range
 ; out: cf - set on error
 ; preserves: eax, ecx, edx, ebp
    and esi, (not _PAGE_OFFSET_MASK)
    and edi, (not _PAGE_OFFSET_MASK)
    cmp esi, dword [_min_virtual_address]
    cmovb esi, dword [_min_virtual_address]
    cmp esi, edi
    cmc
    jc _map_virtual_address_bound_exit
    mov edx, eax
    mov eax, _SENSITIVE_TEMPORARY
    lea ebx, [edi-1H]
    call _sensitive_linear
    mov eax, edx
_map_virtual_address_bound_exit:
    ret

enum & _DEALLOCATION_VIRTUAL, _DEALLOCATION_PSE, _DEALLOCATION_SHARING
assert (_ALLOCATION_VIRTUAL = _DEALLOCATION_VIRTUAL)
_unmap_one_page_virtual_address:
    xor ecx, ecx
    inc cl
_unmap_virtual_address:
 ; in:
 ;  eax - kind of allocation
 ;  ebx - virtual address to unmap
 ;  ecx - number of page to deallocate
 ; out: cf - set when ebx+edx fall in range of the recursive reserved mapping
 ; preserves: ecx, esi, edi, ebp
 ; note: only deallocate (PTE,PDE PSE), PDE/PDPTE may be used in future (locality principle)
    push ecx esi edi ebp
    jecxz _unmap_virtual_address_carry
    cmp eax, (_DEALLOCATION_VIRTUAL or _DEALLOCATION_PSE or _DEALLOCATION_SHARING)
    ja _unmap_virtual_address_carry
    mov ebp, eax
    test al, _DEALLOCATION_VIRTUAL
    jnz _unmap_virtual_address_perform
    mov eax, ebx
    xor edx, edx
    call _deallocate_pages
    jmp _unmap_virtual_address_exit
_unmap_virtual_address_perform:
    test al, _DEALLOCATION_PSE
    jz _unmap_virtual_address_sanitize
    call _convert_pse_page
    jc _unmap_virtual_address_exit
_unmap_virtual_address_sanitize:
    mov esi, ebx
    shl ecx, _PAGE_TABLE_SHIFT
    lea edi, [ebx+ecx]
    cmp esi, edi
    jae _unmap_virtual_address_carry
    xor eax, eax
    mov al, _SENSITIVE_TEMPORARY
    lea ebx, [edi-1H]
    call _sensitive_linear
    jc _unmap_virtual_address_exit
    mov eax, _unmap_virtual_address_pte
    mov edx, _ITERATE_PTE
    call _iterate_range_linear
    jc _unmap_virtual_address_exit
    mov eax, _unmap_virtual_address_pde
    mov edx, _ITERATE_PDE
    call _iterate_range_linear
    jmp _unmap_virtual_address_exit
_unmap_virtual_address_carry:
    stc
_unmap_virtual_address_exit:
    pop ebp edi esi ecx
    ret
irp _kind*, pde,pte
{
    _unmap_virtual_address_#_kind:
        call _page_present
        cmc
        jnc _unmap_virtual_address_#_kind#_exit
        match =pde, _kind \{ jnz _unmap_virtual_address_#_kind#_exit \}
        match =pte, _kind \{ jz _unmap_virtual_address_#_kind#_exit \}
        mov esi, ebx
        mov edi, ebx
        call _load_entry
        test ebp, _DEALLOCATION_SHARING
        jnz _unmap_virtual_address_#_kind#_clear
        call _deallocate_page
        jc _unmap_virtual_address_#_kind#_exit
    _unmap_virtual_address_#_kind#_clear:
        call _clear_entry
        call _linear_make_no_recursive
        invlpg [ebx]
    _unmap_virtual_address_#_kind#_exit:
        ret
}

_allocate_supervisor_pages:
    xor eax, eax
    mov al, _PE_READ_WRITE
    jmp _allocate_pages

irp _kind*, virtual,frame
{
    _allocate_kernel_#_kind:
        and al, (not _ALLOCATION_HINT)
        or al, _ALLOCATION_VIRTUAL
    match =virtual, _kind
    \{
        mov esi, _KERNEL_VIRTUAL
        mov edi, _FRAME_BUFFER_START
    \}
    match =frame, _kind
    \{
        or al, (_ALLOCATION_PSE)
        mov edx, _kernel_framebuffer
        mov esi, _FRAME_BUFFER_START
        mov edi, _SENSITIVE_TEMPORARY_START
    \}
        test byte [_singleton.pae], 1H
        jz _allocate_kernel_#_kind#_perform
    match =virtual, _kind \{ mov edi, _PAE_FRAME_BUFFER_START \}
    match =frame, _kind
    \{
        mov esi, _PAE_FRAME_BUFFER_START
        mov edi, _PAE_SENSITIVE_TEMPORARY_START
    \}
    _allocate_kernel_#_kind#_perform:
        jmp _map_virtual_address
}

enum & _PAGE_PTE, _PAGE_PDE, _PAGE_PDPTE, _PAGE_PDBR, _PAGE_RAW, _PAGE_WRITABLE, _PAGE_USER, _PAGE_GLOBAL, _PAGE_SIZE,\
    _PAGE_WB, _PAGE_WT, _PAGE_UC, _PAGE_UCM, _PAGE_WP, _PAGE_WC, _PAGE_EXECUTE
_386_CACHE_POLICY = (_PAGE_WB or _PAGE_WT or _PAGE_UC or _PAGE_UCM)
_allocate_pages:
 ; in:
 ;  eax - flags of the newly physical block 
 ;  ecx - count of countinous page which must be reserved (if 0H rounded-up to 1H)
 ; out:
 ;  eax - the first address found in the bitmap with flags
 ;  edx - upper 64-bit of the address (useful if PAE set)
 ;   cf - set if not enough memory is present or ecx = 0H
 ; preserves: ebx, ecx, edi, esi, ebp
 ; note:
 ;  include the PDPTE/PTE/PDE flags in the result (PAT,PCD,PWT,PS,PG,...)
 ;  when ecx > 1H, _allocate_pages is only used for physical allocation and user must never use that function
    push ebx esi edi ebp ecx
    test ecx, ecx
    jz _allocate_pages_carry
    cmp eax, (_PAGE_PTE or _PAGE_PDE or _PAGE_PDPTE or _PAGE_PDBR or _PAGE_RAW or _PAGE_WRITABLE or _PAGE_USER or _PAGE_GLOBAL or _PAGE_SIZE or\
        _386_CACHE_POLICY or _PAGE_WP or _PAGE_WC or _PAGE_EXECUTE)
    ja _allocate_pages_carry
    mov ebx, (_PAGE_PDBR or _PAGE_PDPTE or _PAGE_PDE or _PAGE_PTE or _PAGE_RAW)
    call _ensure_flags_exclusive
    jc _allocate_pages_carry+1H
    xor edx, edx
    xor esi, esi
    test al, _PAGE_RAW
    jz _allocate_pages_raw
    test eax, (not (_PAGE_RAW or _PAGE_SIZE))
    jnz _allocate_pages_carry
    test eax, _PAGE_SIZE
    jz _allocate_pages_perform
    mov edx, (_PE_IS_PDE or _PDE_SIZE)
    jmp _allocate_pages_perform
_allocate_pages_raw:
    test al, _PAGE_PDBR
    jz _allocate_pages_pdbr
    test eax, (not (_PAGE_PDBR or _386_CACHE_POLICY))
    jnz _allocate_pages_carry
    jmp _allocate_pages_present
_allocate_pages_pdbr:
    or dl, _PE_PRESENT
    test al, _PAGE_PDE
    jz _allocate_pages_present
    or edx, _PE_IS_PDE
_allocate_pages_present:
    test al, _PAGE_PDPTE
    jz _allocate_pages_pdpt
    test byte [_singleton.pae], 1H
    jz _allocate_pages_carry
    test eax, (not (_PAGE_PDPTE or _386_CACHE_POLICY))
    jnz _allocate_pages_carry
_allocate_pages_pdpt:
    mov ebx, (_386_CACHE_POLICY or _PAGE_WP or _PAGE_WC)
    test eax, ebx
    jnz _allocate_pages_cache
    or eax, _PAGE_WB
_allocate_pages_cache:
    call _ensure_flags_exclusive
    jc _allocate_pages_carry+1H
    test al, _PAGE_WRITABLE
    jz _allocate_pages_userspace
    or dl, _PE_READ_WRITE
_allocate_pages_userspace:
    test al, _PAGE_USER
    jz _allocate_pages_next
    or dl, _PE_USER
_allocate_pages_next:
    test al, _PAGE_GLOBAL
    jz _allocate_pages_size
    test byte [_singleton.pge], 1H
    jz _allocate_pages_carry
    test al, _PAGE_PTE
    jnz _allocate_pages_global
    test eax, _PAGE_SIZE
    jz _allocate_pages_carry
_allocate_pages_global:
    or edx, _PE_GLOBAL
_allocate_pages_size:
    test eax, _PAGE_SIZE
    jz _allocate_pages_transform
    test byte [_singleton.pse], 1H
    jz _allocate_pages_carry
    test al, _PAGE_PDE
    jz _allocate_pages_carry
    or dl, _PDE_SIZE
_allocate_pages_transform:
    xor ecx, ecx
    test eax, _PAGE_WB
    mov cl, _MEMORY_WB
    jnz _allocate_pages_execute
    test eax, _PAGE_WT
    mov cl, _MEMORY_WT
    jnz _allocate_pages_execute
    test eax, _PAGE_UC
    mov cl, _MEMORY_UC
    jnz _allocate_pages_execute
    test eax, _PAGE_UCM
    mov cl, _MEMORY_UCM
    jnz _allocate_pages_execute
    test byte [_singleton.pat], 1H
    jz _allocate_pages_carry
    mov edi, _PDE_PS_PAT
    test cl, _PAGE_PDE
    jz _allocate_pages_protect
    test eax, _PAGE_SIZE
    jz _allocate_pages_carry
    mov edi, _PTE_PAT
_allocate_pages_protect:
    test eax, _PAGE_WP
    mov ecx, _MEMORY_WP
    jnz _allocate_pages_attributes
    test byte [_singleton.wc], 1H
    jz _allocate_pages_carry
    mov ecx, _MEMORY_WC
_allocate_pages_attributes:
    xor ecx, edi
_allocate_pages_execute:
    or edx, ecx
    test eax, _PAGE_EXECUTE
    jz _allocate_pages_perform
    test byte [_singleton.nx], 1H
    jz _allocate_pages_carry
    or edx, (_PAE_XD shr 020H)
_allocate_pages_perform:
    mov ecx, dword [esp]
    test eax, _PAGE_SIZE
    jz _allocate_pages_search
    inc esi
    call _convert_pse_page
    jc _allocate_pages_carry+1H
_allocate_pages_search:
    mov eax, _frame
    mov edi, edx
    xor ebx, ebx
    xor edx, edx
    call _bitmap_search
    jc _allocate_pages_carry+1H
    mov ebp, edx
    mov esi, _BITMAP_RESET
    xchg esi, edi
    call _bitmap_update
    mov edx, ebp
    call _convert_bitmap_linear
    test edx, edx
    jz _allocate_pages_flags
    test byte [_singleton.pae], 1H
    jnz _allocate_pages_flags
    mov ecx, dword [esp] ; _deallocate_pages call _convert_pse_page also
    call _deallocate_pages
    jmp _allocate_pages_carry
_allocate_pages_flags:
    mov edi, _PAE_FLAGS_UPPER_MASK
    and edi, esi
    and esi, (not _PAE_FLAGS_UPPER_MASK)
    lea eax, [ebx+esi]
    or edx, edi
    push eax edx
    mov ebx, eax
    mov ebp, edx
    call _load_temporary_2
    xchg ebx, eax
    xchg ebp, edx
    call _store_temporary_2
    call _base_temporary
    call _clear_pages
    test bl, _PE_PRESENT
    jz _allocate_pages_disable
    mov eax, ebx
    mov edx, ebp
    call _store_temporary_2
    jmp _allocate_pages_restore
_allocate_pages_disable:
    call _clear_temporary_2
_allocate_pages_restore:
    pop edx eax
    jmp _allocate_pages_carry+1H
_allocate_pages_carry:
    stc
    pop ecx ebp edi esi ebx
    ret

_deallocate_pages:
 ; in:
 ;  eax - target page frame with flags
 ;  edx - upper 32-bit of the target page frame (useful only if PAE)
 ;  ecx - number of consecutive frame to deallocate
 ; out: cf - set when the number of wanted free block does not correspond to the reality
 ; preserves: ebx, ecx, edx, esi, edi, ebp
 ; note: automatically remove the flags in eax
    push ebx ecx edx edi
    test eax, _PE_IS_PDE
    jz _deallocate_pages_convert
    test al, _PDE_SIZE
    jz _deallocate_pages_convert
    call _convert_pse_page
    jc _deallocate_pages_exit
_deallocate_pages_convert:
    mov ebx, eax
    mov eax, _frame
    call _convert_linear_bitmap
    mov edi, _BITMAP_RESET
    call _bitmap_inverse
_deallocate_pages_exit:
    pop edi edx ecx ebx
    ret

struct _allocation_functors _pte*, _pde*, _pdpte*
    .pte:   dd (_pte)
    .pde:   dd (_pde)
    .pdpte: dd (_pdpte)
ends

_user_ro_page           _allocation_functors _allocate_user_ro_page, _allocate_user_pde, _allocate_user_pdpte       ; Rwxb
_user_rw_page           _allocation_functors _allocate_user_rw_page, _allocate_user_pde, _allocate_user_pdpte       ; RWxb
_user_xd_ro_page        _allocation_functors _allocate_user_xd_ro_page, _allocate_user_pde, _allocate_user_pdpte    ; RwXb
_user_xd_rw_page        _allocation_functors _allocate_user_xd_rw_page, _allocate_user_pde, _allocate_user_pdpte    ; RWXb
_user_big_ro_page       _allocation_functors 0H, _allocate_user_big_ro_page, _allocate_user_pdpte                   ; RwxB
_user_big_rw_page       _allocation_functors 0H, _allocate_user_big_rw_page, _allocate_user_pdpte                   ; RWxB
_user_big_xd_ro_page    _allocation_functors 0H, _allocate_user_big_xd_ro_page, _allocate_user_pdpte                ; RwXB
_user_big_xd_rw_page    _allocation_functors 0H, _allocate_user_big_xd_rw_page, _allocate_user_pdpte                ; RWXB
_user_vdso              _allocation_functors _allocate_user_vdso, _allocate_user_pde, _allocate_user_pdpte

_kernel_rw_page         _allocation_functors _allocate_kernel_rw_page, _allocate_kernel_pde, _allocate_kernel_pdpte
_kernel_big_rw_page     _allocation_functors 0H, _allocate_kernel_big_rw_page, _allocate_kernel_pdpte
_kernel_framebuffer     _allocation_functors 0H, _allocate_kernel_framebuffer, _allocate_kernel_pdpte
irp _kind*, local,io
{
_kernel_#_kind#_apic_base _allocation_functors _allocate_kernel_#_kind#_apic_base,\
    _allocate_kernel_pde, _allocate_kernel_pdpte
}

_allocate_pdbr:
    mov eax, _PAGE_PDBR
    jmp _allocate_page

_allocate_kernel_physical:
    xor eax, eax
    mov al, _PAGE_RAW
    jmp _allocate_pages

_allocate_user_pdpte:
_allocate_kernel_pdpte:
    mov eax, _PAGE_PDPTE
    jmp _allocate_page

_allocate_user_pde:
    mov eax, (_PAGE_PDE or _PAGE_USER or _PAGE_WRITABLE)
    jmp _allocate_page
_allocate_kernel_pde:
    mov eax, (_PAGE_PDE or _PAGE_WRITABLE)
    jmp _allocate_page

_allocate_user_ro_page:
    mov eax, (_PAGE_PTE or _PAGE_USER)
    jmp _allocate_page
_allocate_user_rw_page:
    mov eax, (_PAGE_PTE or _PAGE_USER or _PAGE_WRITABLE)
    jmp _allocate_page
_allocate_user_big_ro_page:
    mov eax, (_PAGE_PDE or _PAGE_USER or _PAGE_SIZE)
    jmp _allocate_page
_allocate_user_big_rw_page:
    mov eax, (_PAGE_PDE or _PAGE_USER or _PAGE_WRITABLE or _PAGE_SIZE)
    jmp _allocate_page
_allocate_user_xd_ro_page:
    mov eax, (_PAGE_PTE or _PAGE_USER or _PAGE_EXECUTE)
    jmp _allocate_user_big_xd_rw_page+5H
_allocate_user_xd_rw_page:
    mov eax, (_PAGE_PTE or _PAGE_USER or _PAGE_WRITABLE or _PAGE_EXECUTE)
    jmp _allocate_user_big_xd_rw_page+5H
_allocate_user_big_xd_ro_page:
    mov eax, (_PAGE_PDE or _PAGE_USER or _PAGE_SIZE or _PAGE_EXECUTE)
    jmp _allocate_user_big_xd_rw_page+5H
_allocate_user_big_xd_rw_page:
    mov eax, (_PAGE_PDE or _PAGE_USER or _PAGE_SIZE or _PAGE_WRITABLE or _PAGE_EXECUTE)
    test byte [_singleton.nx], 1H
    jnz _allocate_page
    xor eax, _PAGE_EXECUTE
    jmp _allocate_page
_allocate_user_vdso:
    mov eax, dword [_kernel_vdso]
    mov edx, dword [_kernel_vdso+4H]
    ret

_allocate_kernel_rw_page:
    mov eax, (_PAGE_PTE or _PAGE_WRITABLE or _PAGE_GLOBAL)
    jmp _allocate_kernel_big_rw_page+5H
_allocate_kernel_big_rw_page:
    mov eax, (_PAGE_PDE or _PAGE_WRITABLE or _PAGE_SIZE or _PAGE_GLOBAL)
    test byte [_singleton.pge], 1H
    jnz _allocate_page
    xor al, _PAGE_GLOBAL
    jmp _allocate_page

_allocate_kernel_framebuffer:
 ; in: ecx - count of framebuffer allocation
    mov eax, dword [_current_modeinfo.physical]
    and eax, (not _PSE_OFFSET_MASK)
    dec ecx
    shl ecx, _PAE_PAGE_DIRECTORY_SHIFT
    test byte [_singleton.pae], 1H
    jnz _allocate_kernel_framebuffer_attribute
    shl ecx, (_PAGE_DIRECTORY_SHIFT - _PAE_PAGE_DIRECTORY_SHIFT)
_allocate_kernel_framebuffer_attribute:
    add eax, ecx
    jc _allocate_kernel_framebuffer_exit
    or eax, (_PE_IS_PDE or _PDE_SIZE or _PE_READ_WRITE or _PE_PRESENT)
    xor edx, edx
_allocate_kernel_framebuffer_exit:
    ret

irp _kind*, local,io
{
_allocate_kernel_#_kind#_apic_base:
    mov eax, dword [_#_kind#_apic_base]
    or al, (_PE_READ_WRITE or _PE_PRESENT)
    xor edx, edx
    test byte [_singleton.pat], 1H
    jz $+5H
    or eax, _MEMORY_UC
    ret
}

irp _kind*, _allocate,_deallocate
{
_kind#_page:
    push ecx
    xor ecx, ecx
    inc cl
    call _kind#_pages
    pop ecx
    ret
}

_allocate_copy_flags:
 ; in:
 ;  eax - lower half address (with flags)
 ;  edx - upper half address (with flags)
 ; out:
 ;  eax - lower half result (flags copied)
 ;  edx - upper half result (flags copied)
 ;   cf - set on error
 ; preserves: ebx, ecx, esi, edi, ebp
    and eax, _PAGE_OFFSET_MASK_PDE_PAT
    and edx, (_PAE_XD shr 020H)
    push eax edx
    mov eax, _PAGE_RAW
    test dword [esp+4H], _PE_IS_PDE
    jz _allocate_copy_flags_reflag
    test byte [esp+4H], _PDE_SIZE
    jz _allocate_copy_flags_reflag
    or eax, _PAGE_SIZE
    jmp _allocate_copy_flags_invoke
_allocate_copy_flags_reflag:
    and dword [esp+4H], _PAGE_OFFSET_MASK
_allocate_copy_flags_invoke:
    call _allocate_page
    jc _allocate_copy_flags_exit
    or eax, dword [esp+4H]
    or edx, dword [esp]
_allocate_copy_flags_exit:
    lea esp, [esp+8H]
    ret

enum _LINEAR_NO_RECURSIVE, _LINEAR_SINGLE_RECURSIVE, _LINEAR_DOUBLE_RECURSIVE, _LINEAR_TRIPLE_RECURSIVE
_linear_make_no_recursive:
    xor eax, eax
    mov al, _LINEAR_NO_RECURSIVE
    jmp _linear_control
_linear_make_single_recursive:
    xor eax, eax
    mov al, _LINEAR_SINGLE_RECURSIVE
    jmp _linear_control
_linear_make_double_recursive:
    xor eax, eax
    mov al, _LINEAR_DOUBLE_RECURSIVE
    jmp _linear_control
_linear_make_triple_recursive:
    xor eax, eax
    mov al, _LINEAR_TRIPLE_RECURSIVE
_linear_control:
 ; in:
 ;  eax - kind of update to do on the linear address
 ;  ebx - virtual address
 ; out:
 ;  ebx - virtual address updated
 ;   cf - set when eax is ill formed or try to make triple recursive when PAE not activate
 ; preserves: ecx, edx, edi, esi, ebp
 ; note: the resulting address is not checked for deferencing and PSE is not checked also
    push ecx edx edi
    mov edx, eax
    ;mov eax, _SENSITIVE_RECURSIVE
    ;call _sensitive_linear
    ;jc _linear_control_carry+1H
    mov edi, ebx
    and edi, (not _PAGE_OFFSET_MASK)
    cmp edx, _LINEAR_TRIPLE_RECURSIVE
    ja _linear_control_carry
    mov eax, dword [_linear_control_table+edx*4H]
    xchg edi, eax
    call edi ; function pointer in _linear_control_table don't affect the flag
    jnz _linear_control_relevant
    test byte [_singleton.pae], 1H
    jz _linear_control_carry
    jmp _linear_control_reverse
_linear_control_relevant:
    test byte [_singleton.pae], 1H
    jz _linear_control_continue
_linear_control_reverse:
    cmp eax, _PAE_PDPT_RECURSIVE_VIRTUAL
    jnz _linear_control_restore_1
    mov ecx, _linear_control_shift_table+018H
    mov edx, _linear_triple_shift_left
    jmp _linear_control_pae_convert
_linear_control_restore_1:
    and eax, (not (_PAE_PAGE_TABLE_MASK or _PAGE_OFFSET_MASK))
    cmp eax, _PAE_RECURSIVE_VIRTUAL
    jnz _linear_control_restore_2
    mov ecx, _linear_control_shift_table+010H
    mov edx, _linear_double_shift_left_pae
    jmp _linear_control_pae_convert
_linear_control_restore_2:
    cmp eax, _PAE_PTE_RECURSIVE_BASE
    jb _linear_control_adjust_pae
    mov ecx, _linear_control_shift_table+008H
    mov edx, _linear_shift_left_pae
    jmp _linear_control_pae_convert
_linear_control_continue:
    cmp eax, _PAGE_DIRECTORY_LINEAR
    jz _linear_control_match_2
    and eax, (not (_PAGE_TABLE_MASK or _PAGE_OFFSET_MASK))
    cmp eax, _RECURSIVE_VIRTUAL
    jz _linear_control_match_3
    jmp _linear_control_match_1
_linear_control_pae_convert:
    cmp edi, ecx
    jz _linear_control_exit+1H
    call edx
_linear_control_adjust_pae:
    add edi, 4H
_linear_control_match_1:
    call dword [edi]
    jmp _linear_control_exit
_linear_control_match_2:
    call ecx
    jmp _linear_control_exit
_linear_control_match_3:
    call edx
_linear_control_exit:
    clc
    jmp _linear_control_carry+1H
_linear_control_carry:
    stc
    pop edi edx ecx
    ret
_linear_control_table:
    dd _linear_control_no_recursive
    dd _linear_control_single_recursive
    dd _linear_control_double_recursive
    dd _linear_control_triple_recursive
_linear_control_no_recursive:
    mov ecx, _linear_double_shift_left
    mov edx, _linear_shift_left
    mov edi, _linear_control_shift_table+000H
    ret
_linear_control_single_recursive:
    mov ecx, _linear_shift_left
    mov edx, _nothing
    mov edi, _linear_control_shift_table+008H
    ret
_linear_control_double_recursive:
    mov ecx, _nothing
    mov edx, _linear_shift_right
    mov edi, _linear_control_shift_table+010H
    ret
_linear_control_triple_recursive:
    mov edi, _linear_control_shift_table+018H
    ret
_linear_control_shift_table:
    dd _nothing
    dd _nothing
    dd _linear_shift_right
    dd _linear_shift_right_pae
    dd _linear_double_shift_right
    dd _linear_double_shift_right_pae
    dd _linear_triple_shift_right
    dd _linear_triple_shift_right
_linear_shift_left:
    and bl, (not 011B)
    shl ebx, (_PAGE_TABLE_SHIFT - 2H)
    ret
_linear_shift_left_pae:
    sub ebx, _PAE_PTE_RECURSIVE_BASE
    and bl, (not 111B)
    shl ebx, (_PAE_PAGE_DIRECTORY_SHIFT - _PAGE_TABLE_SHIFT)
    ret
_linear_double_shift_left:
    and bl, (not 011B)
    shl ebx, (_PAGE_DIRECTORY_SHIFT - 2H)
    ret
_linear_double_shift_left_pae:
    and bl, (not 111B)
    shl ebx, (_PAE_PAGE_DIRECTORY_POINTER_SHIFT - _PAGE_TABLE_SHIFT)
    ret
_linear_triple_shift_left:
    and bl, (not 111B)
    shl ebx, (_PAE_PAGE_DIRECTORY_POINTER_SHIFT - 3H)
    ret
_linear_shift_right:
    shr ebx, (_PAGE_TABLE_SHIFT - 2H)
    and bl, (not 011B)
    or ebx, _RECURSIVE_VIRTUAL
    ret
_linear_shift_right_pae:
    shr ebx, (_PAE_PAGE_DIRECTORY_SHIFT - _PAGE_TABLE_SHIFT)
    and bl, (not 111B)
    add ebx, _PAE_PTE_RECURSIVE_BASE
    ret
_linear_double_shift_right:
    shr ebx, (_PAGE_DIRECTORY_SHIFT - 2H)
    and bl, (not 011B)
    or ebx, ((_PAGE_DIRECTORY_INDEX shl _PAGE_DIRECTORY_SHIFT) or (_PAGE_DIRECTORY_INDEX shl _PAGE_TABLE_SHIFT))
    ret
_linear_double_shift_right_pae:
    shr ebx, ((_PAE_PAGE_DIRECTORY_SHIFT - _PAGE_TABLE_SHIFT) shl 1H)
    and bl, (not 111B)
    or ebx, _PAE_RECURSIVE_VIRTUAL
    ret
_linear_triple_shift_right:
    and ebx, _PAE_PAGE_DIRECTORY_POINTER_MASK
    shr ebx, (_PAE_PAGE_DIRECTORY_POINTER_SHIFT - 3H)
    or ebx, _PAE_PDPT_RECURSIVE_VIRTUAL
    ret

_convert_linear_bitmap:
 ; in:
 ;  eax - bitmap pointer object
 ;  ebx - lower linear address (with flags)
 ;  edx - upper linear address (useful only if PAE activate)
 ; out:
 ;  ebx - pointer to the bitmap sequence
 ;  edx - offset to the pointed dword
 ; preserves: eax, ecx, esi, edi, ebp
    test ebx, _PE_IS_PDE
    jz _convert_linear_bitmap_clear
    test bl, _PDE_SIZE
    jz _convert_linear_bitmap_clear
    and ebx, (not _PDE_PS_PAT)
_convert_linear_bitmap_clear:
    and edx, (not _PAE_FLAGS_UPPER_MASK)
    shr ebx, _PAGE_TABLE_SHIFT
    shl edx, _PAE_PAGING_LEVEL_BIT
    or ebx, edx
    mov edx, ((_BITMAP_UNIT shl 3H) - 1H)
    and edx, ebx
    shr ebx, 3H
    and bl, (not (_BITMAP_UNIT - 1H))
    lea ebx, [ebx+eax+_bitmap.table]
    ret

_maxphyaddr_high_mask:
 ; out: eax - mask to bitwise-and to obtain the maximal physical address line
 ; preserves: ebx, edx, esi, edi, ebp
    movzx ecx, byte [_singleton.maxphyaddr]
    sub ecx, 020H
    xor eax, eax
    inc al
    shl eax, cl
    dec eax
    ret

_convert_bitmap_linear:
 ; in:
 ;  eax - bitmap pointer object
 ;  ebx - pointer to the bitmap sequence
 ;  edx - offset to the pointed dword
 ; out:
 ;  ebx - lower page entry
 ;  edx - upper page entry (useful only if PAE activate)
 ; preserves: eax, ecx, esi, edi, ebp
    push eax ecx
    sub ebx, eax
    sub ebx, _bitmap.table
    shl ebx, 3H
    add ebx, edx
    mov edx, _PAE_LONG_POINTER_UPPER
    and edx, ebx
    shl ebx, _PAGE_TABLE_SHIFT
    shr edx, _PAE_PAGING_LEVEL_BIT
    call _maxphyaddr_high_mask
    and edx, eax
    pop ecx eax
    ret

_invert_zero_carry:
    clc
    jz $+3H
    stc
    ret

_convert_zero_carry:
    stc
    jz $+3H
    clc
    ret

irp _kind*, set,clear
{
_#_kind#_eflags:
 ; in: eax - new eflags
 ; preserves: ebx, ecx, edx, esi, edi, ebp
    push ebx
    pushfd
    match =set, _kind \{ or al, _EFLAGS_RSVD \}
    and eax, (_EFLAGS_CPUID or _EFLAGS_VIP or _EFLAGS_VIF or _EFLAGS_AC or _EFLAGS_VM or _EFLAGS_RF or _EFLAGS_NT or\
        (011B shl _EFLAGS_IOPL) or _EFLAGS_OF or _EFLAGS_DF or _EFLAGS_IF or _EFLAGS_TF or _EFLAGS_SF or _EFLAGS_ZF or\
        _EFLAGS_AF or _EFLAGS_PF or _EFLAGS_RSVD or _EFLAGS_CF)
    match =clear, _kind \{ not eax \}
    mov ebx, _#_kind#_eflags_lahf
    cmp eax, 0FFH
    jbe $+7H
    mov ebx, _#_kind#_eflags_pushf
    popfd
    jmp ebx
_#_kind#_eflags_lahf:
    lahf
    match =set, _kind \{ or ah, al \}
    match =clear, _kind \{ and ah, al \}
    sahf
    jmp _#_kind#_eflags_exit
_#_kind#_eflags_pushf:
    pushf
    match =set, _kind \{ or dword [esp], eax \}
    match =clear, _kind \{ and dword [esp], eax \}
    popf
_#_kind#_eflags_exit:
    pop ebx
    ret
}

enum & _SET_SF_CF, _SET_SF_ENABLE, _SET_ZF_CF, _SET_ZF_ENABLE
_set_depend_carry:
 ; in: al - bitmask of desired operation, if the bitmask is not a valid one, change nothing
 ; preserves: ebx, ecx, edx, esi, edi, ebp, eflags (except SF, ZF depend on al)
    push edx
    pushf
    cmp al, _SET_ZF_ENABLE
    ja _set_depend_carry_exit
    mov dl, al
    test dl, _SET_SF_ENABLE
    jz _set_depend_carry_next
    and byte [esp], (not _EFLAGS_SF)
    test dl, _SET_SF_CF
    jz _set_depend_carry_sf
    test byte [esp], _EFLAGS_CF
    jz _set_depend_carry_next
    jmp _set_depend_carry_sf_update
_set_depend_carry_sf:
    test byte [esp], _EFLAGS_CF
    jnz _set_depend_carry_next
_set_depend_carry_sf_update:
    or byte [esp], _EFLAGS_SF
_set_depend_carry_next:
    test dl, _SET_ZF_ENABLE
    jz _set_depend_carry_exit
    and byte [esp], (not _EFLAGS_ZF)
    test dl, _SET_ZF_CF
    jz _set_depend_carry_zf
    test byte [esp], _EFLAGS_CF
    jz _set_depend_carry_exit
    jmp _set_depend_carry_zf_update
_set_depend_carry_zf:
    test byte [esp], _EFLAGS_CF
    jnz _set_depend_carry_exit
_set_depend_carry_zf_update:
    or byte [esp], _EFLAGS_ZF
_set_depend_carry_exit:
    popf
    pop edx
    ret

_clear_pages:
 ; in: ecx - count of page to clear
    shl ecx, _PAGE_TABLE_SHIFT
_clear_string:
 ; out: eax = 0H
    xor eax, eax
_store_string:
 ; out: cf - always clear
 ; preserves: eax, ebx, esi, ebp
    jecxz _store_string_exit
    mov edx, ecx
    shr ecx, 2H
    rep stosd
    mov ecx, edx
    and ecx, 011B
    rep stosb
_store_string_exit:
    ret

_copy_string:
 ; preserves: eax, ebx, ebp
 ; note: support overlapped memory
    jecxz _copy_string_exit
    ;cmp edi, esi
    ;jz _copy_string_exit
    ;cmp edi, esi
    ;jb _copy_string_perform
    ;std
    ;lea edi, [edi+ecx-1H]
    ;lea esi, [esi+ecx-1H]
    ;cmp ecx, 4H
    ;jb _copy_string_perform
    ;sub edi, 3H
    ;sub esi, 3H
_copy_string_perform:
    mov edx, ecx
    shr ecx, 2H
    rep movsd
    mov ecx, edx
    and ecx, 011B
    rep movsb
_copy_string_exit:
    cld
    ret

irp _kind*, _clear,_store,_copy
{
    _kind#_string_user:
    call _disable_smap
    call _kind#_string
    jmp _enable_smap
}

_disable_smap:
    test byte [_singleton.smap], 1H
    jz $+5H
    stac
    ret

_enable_smap:
    test byte [_singleton.smap], 1H
    jz $+5H
    clac
    ret

rept 2H i:1H
{
    irp _kind*, _store,_load
    \{
    _kind\#_temporary_#i:
        match =_store, _kind
        \\{
            push edi
            mov edi, _TEMP_#i#_LINEAR_ITSELF
            call _invlpg_temporary_#i
        \\}
        match =_load, _kind
        \\{
            push esi
            mov esi, _TEMP_#i#_LINEAR_ITSELF 
        \\}
        test byte [_singleton.pae], 1H
        jz _kind\#_temporary_#i#_exit
        match =_store, _kind \\{ mov edi, _PAE_TEMP_#i#_LINEAR_ITSELF \\}
        match =_load, _kind \\{ mov esi, _PAE_TEMP_#i#_LINEAR_ITSELF \\}
    _kind\#_temporary_#i#_exit:
        match =_store, _kind
        \\{
            call _store_wp_entry
            pop edi
        \\}
        match =_load, _kind
        \\{
            call _load_entry
            pop esi
        \\}
        ret
    \}

_clear_temporary_#i:
    push eax edx
    mov edi, _TEMP_#i#_LINEAR_ITSELF
    test byte [_singleton.pae], 1H
    jz _clear_temporary_#i#_next
    mov edi, _PAE_TEMP_#i#_LINEAR_ITSELF
_clear_temporary_#i#_next:
    call _clear_entry
    call _invlpg_temporary_#i
    pop edx eax
    ret

_invlpg_temporary_#i:
    push eax ebx ecx edx
    xor eax, eax
    mov ecx, (_TABLE_ENTRY_COUNT * _PAGE_FRAME_SIZE)
    mov ebx, _TEMP_#i#_LINEAR_PTE
    mov edx, _TEMP_#i#_LINEAR_PDE
    test byte [_singleton.pae], 1H
    jz _invlpg_temporary_#i#_loop
    mov ecx, (_PAE_TABLE_ENTRY_COUNT * _PAGE_FRAME_SIZE)
    mov ebx, _PAE_TEMP_#i#_LINEAR_PTE
    mov edx, _PAE_TEMP_#i#_LINEAR_PDE
_invlpg_temporary_#i#_loop:
    invlpg [ebx+eax]
    add eax, _PAGE_FRAME_SIZE
    cmp eax, ecx
    jb _invlpg_temporary_#i#_loop
    invlpg [edx]
    pop edx ecx ebx eax
    ret
}

_invlpg_temporary:
    call _invlpg_temporary_1
    jmp _invlpg_temporary_2

_clear_temporary:
    call _clear_temporary_1
    jmp _clear_temporary_2

_base_temporary:
 ; in: eax - low order base address (with flag)
 ; out:
 ;  esi - temporary 1 offset (PDE/PTE)
 ;  edi - temporary 2 offset (PDE/PTE)
 ; preserves: eax, ebx, ecx, edx, ebp
    test eax, _PE_IS_PDE
    jz _base_temporary_normal
    test al, _PDE_SIZE
    jz _base_temporary_normal
    mov esi, _TEMP_1_LINEAR_PTE
    mov edi, _TEMP_2_LINEAR_PTE
    test byte [_singleton.pae], 1H
    jz _base_temporary_exit
    mov esi, _PAE_TEMP_1_LINEAR_PTE
    mov edi, _PAE_TEMP_2_LINEAR_PTE
    jmp _base_temporary_exit
_base_temporary_normal:
    mov esi, _TEMP_1_LINEAR_PDE
    mov edi, _TEMP_2_LINEAR_PDE
    test byte [_singleton.pae], 1H
    jz _base_temporary_exit
    mov esi, _PAE_TEMP_1_LINEAR_PDE
    mov edi, _PAE_TEMP_2_LINEAR_PDE
_base_temporary_exit:
    ret

_convert_temporary:
 ; in: ebx - temporary mapping
 ; out:
 ;  ebx - opposite temporary mapping
 ;   cf - can't convert the temporary mapping
 ; note: transform a pointer into a temporary mapping (1,2) into the opposite (2,1)
 ; preserves: eax, ecx, edx, esi, edi, ebp
    push eax edx
    mov edx, ebx
    and edx, _PAGE_OFFSET_MASK
    and ebx, (not _PAGE_OFFSET_MASK)
    mov eax, _SENSITIVE_RECURSIVE
    call _sensitive_linear
    jc _convert_temporary_recursive
    mov eax, _SENSITIVE_TEMPORARY
    call _sensitive_linear
    jnc _convert_temporary_exit
    or edx, ebx
    and edx, (_PAE_PAGE_TABLE_MASK or _PAGE_OFFSET_MASK)
    and ebx, (not (_PAE_PAGE_TABLE_MASK or _PAGE_OFFSET_MASK))
    test byte [_singleton.pae], 1H
    jnz _convert_temporary_pae
    or edx, ebx
    and edx, (_PAGE_TABLE_MASK or _PAGE_OFFSET_MASK)
    and ebx, (not (_PAGE_TABLE_MASK or _PAGE_OFFSET_MASK))
    cmp ebx, _TEMP_1_LINEAR_PTE
    jnz _convert_temporary_set
    lea ebx, [edx+_TEMP_2_LINEAR_PTE]
    jmp _convert_temporary_exit+1H
_convert_temporary_set:
    cmp ebx, _TEMP_2_LINEAR_PTE
    jnz _convert_temporary_exit
    lea ebx, [edx+_TEMP_1_LINEAR_PTE]
    jmp _convert_temporary_exit+1H
_convert_temporary_pae:
    cmp ebx, _PAE_TEMP_1_LINEAR_PTE
    jnz _convert_temporary_pae_set
    lea ebx, [edx+_PAE_TEMP_2_LINEAR_PTE]
    jmp _convert_temporary_exit+1H
_convert_temporary_pae_set:
    cmp ebx, _PAE_TEMP_2_LINEAR_PTE
    jnz _convert_temporary_exit
    lea ebx, [edx+_PAE_TEMP_1_LINEAR_PTE]
    jmp _convert_temporary_exit+1H
_convert_temporary_recursive:
    test byte [_singleton.pae], 1H
    jnz _convert_temporary_recursive_pae
    cmp ebx, _TEMP_1_LINEAR_PDE
    jnz _convert_temporary_recursive_set
    lea ebx, [edx+_TEMP_2_LINEAR_PDE]
    jmp _convert_temporary_exit+1H
_convert_temporary_recursive_set:
    cmp ebx, _TEMP_2_LINEAR_PDE
    jnz _convert_temporary_exit
    lea ebx, [edx+_TEMP_1_LINEAR_PDE]
    jmp _convert_temporary_exit+1H
_convert_temporary_recursive_pae:
    cmp ebx, _PAE_TEMP_1_LINEAR_PDE
    jnz _convert_temporary_recursive_pae_set
    lea ebx, [edx+_PAE_TEMP_2_LINEAR_PDE]
    jmp _convert_temporary_exit+1H
_convert_temporary_recursive_pae_set:
    cmp ebx, _PAE_TEMP_2_LINEAR_PDE
    jnz _convert_temporary_exit
    lea ebx, [edx+_PAE_TEMP_1_LINEAR_PDE]
    jmp _convert_temporary_exit+1H
_convert_temporary_exit:
    stc
    pop edx eax
    ret

_convert_virtual_volatile:
 ; in: ebx - virtual pointer
 ; out: ebx - resulting pointer
 ; note: in PAE whe must delete the PDPT index from the pointer
    and ebx, (not _PAGE_OFFSET_MASK)
    shr ebx, (_PAGE_TABLE_SHIFT - 3H)
    test byte [_singleton.pae], 1H
    jnz _convert_virtual_volatile_pae
    shr ebx, 1H
    or ebx, _TEMP_1_LINEAR_PTE
    jmp _convert_virtual_volatile_exit
_convert_virtual_volatile_pae:
    and ebx, (not (_PAE_PAGE_DIRECTORY_POINTER_MASK shr (_PAGE_TABLE_SHIFT - 3H)))
    or ebx, _PAE_TEMP_1_LINEAR_PTE
_convert_virtual_volatile_exit:
    ret

_RESET_THRESHOLD = 1H
_RESET_PAE_THRESHOLD = _PDPT_INDEX_KERNEL
_reset_mapping:
 ; in: esi - PDBR pointer
 ; preserves: ebx, esi, ebp
    push ebx esi
    and esi, (not _PAGE_OFFSET_MASK)
    xor ecx, ecx
    mov cl, _RESET_PAE_THRESHOLD
    test byte [_singleton.pae], 1H
    jnz _reset_mapping_loop
    mov cl, _RESET_THRESHOLD
    mov eax, esi
    xor edx, edx
    jmp _reset_mapping_store
_reset_mapping_loop:
    mov ebx, esi
    call _load_entry
    test al, _PE_PRESENT
    jz _reset_mapping_clear
_reset_mapping_store:
    call _store_temporary_1
    test byte [_singleton.pae], 1H
    jnz _reset_mapping_pae
    mov esi, _TEMP_1_LINEAR_PTE
    mov edi, (_TEMP_2_LINEAR_PTE - ((100000000H - _KERNEL_VIRTUAL) shr (bsf _TABLE_ENTRY_COUNT)))
    jmp _reset_mapping_iterate
_reset_mapping_pae:
    mov esi, _PAE_TEMP_1_LINEAR_PTE
    mov edi, _PAE_TEMP_2_LINEAR_PTE
_reset_mapping_iterate:
    mov eax, _reset_mapping_pte
    mov edx, (_ITERATE_PTE or _ITERATE_CARRY_ERROR)
    call _iterate_range_linear
    jc _reset_mapping_exit
    mov eax, _reset_mapping_pde
    mov edx, (_ITERATE_PDE or _ITERATE_CARRY_ERROR)
    call _iterate_range_linear
    jc _reset_mapping_exit
_reset_mapping_clear:
    test byte [_singleton.pae], 1H
    jz _reset_mapping_update
    mov edi, ebx
    call _clear_entry
    mov esi, edi
_reset_mapping_update:
    loop _reset_mapping_loop
    call _clear_temporary_1
_reset_mapping_exit:
    pop esi ebx
    ret
_reset_mapping_pde:
    mov esi, ebx
    mov edi, ebx
    call _load_entry
    test al, _PE_PRESENT
    jz _reset_mapping_pde_exit
    test eax, _PDE_SIZE
    jz _reset_mapping_pde_deallocate
    test eax, _PE_COW
    jz _reset_mapping_pde_deallocate
    call _update_page_descriptor
    jmp _reset_mapping_pde_update
_reset_mapping_pde_deallocate:
    call _deallocate_page
_reset_mapping_pde_update:
    jc _reset_mapping_pde_exit
    call _clear_entry
_reset_mapping_pde_exit:
    ret
_reset_mapping_pte:
    mov esi, ebx
    mov edi, ebx
    call _linear_make_single_recursive
    test byte [ebx], _PE_PRESENT
    jz _reset_mapping_pte_exit
    test byte [ebx], _PDE_SIZE
    jnz _reset_mapping_pte_exit
    call _load_entry
    test al, _PE_PRESENT
    jz _reset_mapping_pte_exit
    test eax, _PE_COW
    jnz _reset_mapping_pte_cow
    call _deallocate_page
    jmp _reset_mapping_pte_update
_reset_mapping_pte_cow:
    call _update_page_descriptor
_reset_mapping_pte_update:
    jc _reset_mapping_pte_exit
    call _clear_entry
_reset_mapping_pte_exit:
    ret

_default_mapping:
 ; in: esi - PDBR pointer
 ; preserves: ebx, esi, ebp
    push esi ebp
    mov ebp, esi
    and esi, (not _PAGE_OFFSET_MASK)
    call _reset_mapping
    jc _default_mapping_exit
    test byte [_singleton.pae], 1H
    jnz _default_mapping_pae
    mov eax, ebp
    xor edx, edx
    call _store_temporary_1
    mov esi, (_TEMP_2_LINEAR_PTE - ((100000000H - _KERNEL_VIRTUAL) shr (bsf _TABLE_ENTRY_COUNT)))
    mov edi, _TEMP_2_LINEAR_PTE
    jmp _default_mapping_iterate
_default_mapping_pae:
    add esi, (_PDPT_INDEX_KERNEL shl 3H)
    mov edi, esi
    call _load_entry
    test al, _PE_PRESENT
    jnz _default_mapping_setup
    mov eax, _PAGE_PDPTE
    call _allocate_page
    jc _default_mapping
_default_mapping_setup:
    and eax, _PDPTE_RESERVED_BIT
    call _store_entry
    call _store_temporary_1
    mov edi, esi
    mov eax, ebp
    xor edx, edx
    call _store_wp_entry
    mov esi, _PAE_TEMP_1_LINEAR_PTE
    mov edi, _PAE_TEMP_2_LINEAR_PTE
_default_mapping_iterate:
    mov eax, _default_mapping_pde
    mov edx, (_ITERATE_PDE or _ITERATE_CARRY_ERROR)
    call _iterate_range_linear
    jc _default_mapping_exit
    call _clear_temporary_1
_default_mapping_exit:
    pop ebp esi
    ret
_default_mapping_pde:
 ; in: ebx - (pdpt/pd) pointer for recursive mapping
    mov edi, ebx
    mov ebx, _KERNEL_VIRTUAL
    call _linear_make_double_recursive
    mov eax, edi
    and eax, _PAGE_OFFSET_MASK
    and ebx, (not _PAGE_OFFSET_MASK)
    lea esi, [ebx+eax]
    shr eax, 2H
    test byte [_singleton.pae], 1H
    jnz _default_mapping_pde_pae
    cmp eax, _TEMP_2_INDEX
    ja _default_mapping_pde_recursive
    jz _default_mapping_pde_clear
    cmp eax, _TEMP_1_INDEX
    jz _default_mapping_pde_clear
    jmp _default_mapping_pde_copy
_default_mapping_pde_pae:
    shr eax, 1H
    cmp eax, _PTE_INDEX_RECURSIVE_KERNEL 
    ja _default_mapping_pde_recursive
    jnz _default_mapping_pde_next    
    mov esi, _PAE_TEMP_1_LINEAR_ITSELF
    call _load_entry
    jmp _default_mapping_pde_update
_default_mapping_pde_next:
    cmp eax, _PAE_TEMP_1_INDEX
    jae _default_mapping_pde_clear
_default_mapping_pde_copy:
    call _copy_entry
    jmp _default_mapping_pde_exit
_default_mapping_pde_clear:
    call _clear_entry
    jmp _default_mapping_pde_exit
_default_mapping_pde_recursive:
    mov eax, ebp
    xor edx, edx
_default_mapping_pde_update:
    call _store_wp_entry
_default_mapping_pde_exit:
    ret

_DUPLICATE_THRESHOLD = 1H
_DUPLICATE_PAE_THRESHOLD = _PDPT_INDEX_RECURSIVE
_duplicate_mapping:
 ; in:
 ;  esi - source PDBR pointer (must be in <4G)
 ;  edi - destination PDBR pointer
    push ebx esi edi ebp
    mov esi, edi
    call _default_mapping
    jc _duplicate_mapping_exit
    mov esi, dword [esp+8H]
    mov edi, dword [esp+4H]
    and esi, (not _PAGE_OFFSET_MASK)
    and edi, (not _PAGE_OFFSET_MASK)
    mov ebp, edi
    xor ecx, ecx
    mov cl, _DUPLICATE_PAE_THRESHOLD
    test byte [_singleton.pae], 1H
    jnz _duplicate_mapping_loop
    mov cl, _DUPLICATE_THRESHOLD
    xor edx, edx
    mov eax, edi
    call _store_temporary_2
    mov eax, esi
    call _store_temporary_1
    jmp _duplicate_mapping_perform
_duplicate_mapping_loop:
    cmp cl, 1H
    jnz _duplicate_mapping_load
    mov esi, ebp
_duplicate_mapping_load:
    call _load_entry
    mov ebx, esi
    test al, _PE_PRESENT
    jnz _duplicate_mapping_pgdir
    call _clear_entry
    mov ebp, edi
    jmp _duplicate_mapping_update
_duplicate_mapping_pgdir:
    call _store_temporary_1
    cmp cl, 1H
    jnz _duplicate_mapping_copy
    mov esi, dword [esp+4H]
    mov edi, (_PAE_TEMP_1_LINEAR_PDE + (_PTE_INDEX_RECURSIVE_1 shl 3H))
    call _copy_wp_entry
    call _copy_wp_entry
    call _copy_wp_entry
    jmp _duplicate_mapping_clear
_duplicate_mapping_copy:
    call _allocate_copy_flags
    jc _duplicate_mapping_exit
    call _store_entry
    mov ebp, edi
    call _store_temporary_2
_duplicate_mapping_perform:
    mov esi, _PAE_TEMP_1_LINEAR_PTE
    mov edi, _PAE_TEMP_2_LINEAR_PTE
    test byte [_singleton.pae], 1H
    jnz _duplicate_mapping_invoke
    mov esi, _TEMP_1_LINEAR_PTE
    mov edi, (_TEMP_2_LINEAR_PTE - ((100000000H - _KERNEL_VIRTUAL) shr (bsf _TABLE_ENTRY_COUNT)))
_duplicate_mapping_invoke:
    mov eax, _duplicate_mapping_pde
    mov edx, (_ITERATE_PDE or _ITERATE_CARRY_ERROR)
    call _iterate_range_linear
    jc _duplicate_mapping_exit
    mov eax, _duplicate_mapping_pte
    mov edx, (_ITERATE_PTE or _ITERATE_CARRY_ERROR)
    call _iterate_range_linear
    jc _duplicate_mapping_exit
_duplicate_mapping_update:
    mov esi, ebx
    mov edi, ebp
    dec ecx
    jnz _duplicate_mapping_loop
_duplicate_mapping_clear:
    call _clear_temporary
_duplicate_mapping_exit:
    pop ebp edi esi ebx
    ret

_duplicate_mapping_pde:
    mov esi, ebx
    call _convert_temporary
    jc _duplicate_mapping_pde_exit
    mov edi, ebx
    test byte [esi], _PE_PRESENT
    jnz _duplicate_mapping_pde_present
    call _clear_entry
    jmp _duplicate_mapping_pde_exit
_duplicate_mapping_pde_present:
    test byte [esi], _PDE_SIZE
    jnz _duplicate_mapping_pde_pse
    call _load_entry
    call _allocate_copy_flags
    jc _duplicate_mapping_pde_exit
    jmp _duplicate_mapping_pde_store
_duplicate_mapping_pde_pse:
    mov eax, _DUPLICATE_MAPPING_PDE
    call _duplicate_mapping_cow
    jc _duplicate_mapping_pde_exit
_duplicate_mapping_pde_store:
    call _store_entry
_duplicate_mapping_pde_exit:
    ret

_duplicate_mapping_pte:
    mov esi, ebx
    call _convert_temporary
    jc _duplicate_mapping_pte_exit
    mov edi, ebx
    mov ebx, esi
    call _linear_make_single_recursive
    test byte [ebx], _PE_PRESENT
    jz _duplicate_mapping_pte_exit
    test byte [ebx], _PDE_SIZE
    jnz _duplicate_mapping_pte_exit
    xor eax, eax
    mov al, _DUPLICATE_MAPPING_PTE
    call _duplicate_mapping_cow
    jc _duplicate_mapping_pte_exit
    call _store_entry
_duplicate_mapping_pte_exit:
    ret

enum _DUPLICATE_MAPPING_PDE, _DUPLICATE_MAPPING_PTE
_duplicate_mapping_cow:
 ; in:
 ;  eax - [esi] kind
 ;  esi - source pointer of entry containing edx:eax
 ; out:
 ;  eax - updated lower 32-bit PTE/PDE
 ;  edx - updated upper 32-bit PTE/PDE
 ;   cf - set on error
 ; presevres: edi
    push eax
    mov ebp, esi
    call _load_entry
    push edi edx eax
    cmp dword [esp+00CH], (_DUPLICATE_MAPPING_PTE + 1H)
    cmc
    jc _duplicate_mapping_cow_exit
    test al, _PE_PRESENT
    jz _duplicate_mapping_cow_exit
    test eax, _PE_COW
    jnz _duplicate_mapping_cow_update
    xor eax, eax
    mov al, _ALLOCATION_VIRTUAL
    mov edi, _page_descriptor_cache
    call _allocate_from_cache
    jc _duplicate_mapping_cow_exit
    mov eax, (_PE_COW or _PE_READ_WRITE)
    test byte [esp], _PE_READ_WRITE
    jnz _duplicate_mapping_cow_reflags
    or eax, _PE_RDO
    xor al, _PE_READ_WRITE
_duplicate_mapping_cow_reflags:
    xor dword [ebp], eax ; toggle on COW and off READ_WRITE in source
    xor dword [esp], eax ; toggle on COW and off READ_WRITE in destination
    mov eax, dword [esp]
    mov edx, dword [esp+4H]
    and eax, (not _PAGE_OFFSET_MASK)
    cmp byte [esp+00CH], _DUPLICATE_MAPPING_PTE
    jz _duplicate_mapping_cow_execute
    and eax, (not _PAGE_OFFSET_MASK_PDE_PAT)
_duplicate_mapping_cow_execute:
    and edx, (not (_PAE_XD shr 020H))
    xor ecx, ecx
    mov cl, 2H
    mov dword [ebx+_page_descriptor.lower], eax
    mov dword [ebx+_page_descriptor.upper], edx
    mov dword [ebx+_page_descriptor.count], ecx
    mov cl, _page_descriptor.list
    call _doubly_linked
    push ebx
    mov edx, _page_descriptor_head
    call _assign_list_esp
    jmp _duplicate_mapping_cow_exit
_duplicate_mapping_cow_update:
    mov eax, _page_descriptor_head
    mov ecx, _page_descriptor.list
    xor edx, edx
    mov dl, _LIST_FORWARD
    mov esi, _update_page_descriptor_match
    call _find_list
    jc _duplicate_mapping_cow_exit
    inc dword [ebx+_page_descriptor.count]
_duplicate_mapping_cow_exit:
    pop eax edx edi
    lea esp, [esp+4H]
    ret

_swap_in:
 ; XXX - read and write to disk
    ret

_swap_out:
 ; XXX - read and write to disk
    ret

_update_page_descriptor:
 ; in:
 ;  eax - lower physical address of the COW page
 ;  edx - upper physical address of the COW page
 ; out:
 ;  cf - set error
 ;  zf - only relevant when cf is clear, set when no longer page descriptor refer to edx:eax
 ; preserves: eax, edx, ecx, esi, edi
    push ecx esi edi edx eax
    mov eax, _page_descriptor_head
    mov ecx, _page_descriptor.list
    xor edx, edx
    mov dl, _LIST_FORWARD
    mov esi, _update_page_descriptor_match
    call _find_list
    jc _update_page_descriptor_exit
    dec dword [ebx+_page_descriptor.count]
    jnz _update_page_descriptor_exit
    xor edx, edx
    mov esi, ebx
    call _assign_list
    jc _update_page_descriptor_exit
    mov edi, _page_descriptor_cache
    call _deallocate_from_cache
    jc _update_page_descriptor_exit
    xor eax, eax
_update_page_descriptor_exit:
    pop eax edx edi esi ecx
    ret
_update_page_descriptor_match:
 ; in:
 ;  [esp+_FIND_LIST_REMAINS] - lower 32-bit from (PDPT/PD/PT)E
 ;  [esp+_FIND_LIST_REMAINS+4H] - upper 32-bit from (PDPT/PD/PT)E
 ; out: cf - set if match
    mov ebp, [esp+_FIND_LIST_REMAINS]
    and ebp, (not _PAGE_OFFSET_MASK)
    cmp dword [ebx+_page_descriptor.lower], ebp
    jnz _update_page_descriptor_match_exit
    mov ebp, [esp+_FIND_LIST_REMAINS+4H]
    and ebp, (not (_PAE_XD shr 020H))
    cmp dword [ebx+_page_descriptor.upper], ebp
_update_page_descriptor_match_exit:
    jmp _convert_zero_carry

_copy_on_write:
 ; in: ebx - virtual address (assume low order 12-bit are clear)
 ; out:
 ;  cf - set if error
 ;  sf - indicate if it's effectively a COW case
 ; preserves: ebx, esi, edi, ebp
 ; note:
 ;  When PAE activate, we can't use 64 pointer because we are still in 32-bit.
 ;  So we must allocate the freshly page in the current mapping and remove it after the copy.
    push ebx esi edi ebp
    call _page_present
    jc _copy_on_write_exit
    jz _copy_on_write_pse
    call _linear_make_single_recursive
    jmp _copy_on_write_check
_copy_on_write_pse:
    call _linear_make_double_recursive
    and dword [esp+00CH], (not _PAE_PSE_OFFSET_MASK)
    test byte [_singleton.pae], 1H
    jnz _copy_on_write_check
    and dword [esp+00CH], (not _PSE_OFFSET_MASK)
_copy_on_write_check:
    test dword [ebx], _PE_COW
    jz _copy_on_write_exit
    test dword [ebx], _PE_RDO
    jnz _copy_on_write_exit
    xor dword [ebx], (_PE_COW or _PE_READ_WRITE) ; toggle off COW and on READ_WRITE
    mov edi, ebx
    mov esi, ebx
    call _load_entry
    call _update_page_descriptor
    jc _copy_on_write_exit
    jz _copy_on_write_signal
    call _store_temporary_1
    call _allocate_copy_flags
    jc _copy_on_write_exit
    call _store_entry
    xor ecx, ecx
    inc cl
    test eax, _PE_IS_PDE
    jz _copy_on_write_4096
    test al, _PDE_SIZE
    jz _copy_on_write_4096
    call _convert_pse_page
_copy_on_write_4096:
    shl ecx, _PAGE_TABLE_SHIFT
    call _base_temporary
    mov edi, dword [esp+00CH]
    call _copy_string
    call _clear_temporary_1
_copy_on_write_signal:
    xor eax, eax
    mov al, _EFLAGS_SF
    call _set_eflags   
_copy_on_write_exit:
    pop ebp edi esi ebx
    ret

_page_fault:
 ; in: [esp+4H] - last retframe
 ; note: format of the error code pushed on the stack
 ;     P - page present or not
 ;   R/W - access was perfomed by a memory read (if 0H) or a memory write otherwise
 ;   U/S - access was perfomed by a supervisor (if 0H) or a user otherwise
 ;  RSVD - fault caused by a write into a reserved bit (if 1H) or not otherwise
 ;   I/D - fault caused by an instruction fetch (if 1H) or not otherwise. This is meaningful only with the XD bit
    lea ebx, [esp+4H]
    mov esi, dword [_current]
    inc dword [esi+_process.pfcount]
    mov eax, dword [ebx+_x86_register.error]
    mov ebx, cr2
    and ebx, (not _PAGE_OFFSET_MASK)
    test al, _PF_RSVD
    jnz _panic
    test al, _PF_ID
    jnz _page_fault_segfault
    test al, _PF_P
    jz _page_fault_expand
    test al, _PF_RW
    jz _page_fault_expand
    call _copy_on_write
    jc _page_fault_segfault
    js _page_fault_exit
_page_fault_expand:
    xor ecx, ecx
    inc cl
    mov edi, _user_rw_page
    cmp ebx, dword [esi+_process.mnbrk]
    jb _page_fault_segfault
    mov eax, dword [esi+_process.break]
    cmp eax, dword [esi+_process.ustck]
    setb dl
    test dl, dl
    jz _page_fault_terminate
    cmp ebx, eax
    jb _page_fault_allocate
    cmp ebx, dword [esi+_process.ustck]
    jae _page_fault_segfault
    mov edi, _user_xd_rw_page
    mov ebp, ebx
    xchg ebx, dword [esi+_process.ustck]
    sub ebx, dword [esi+_process.ustck]
    shr ebx, _PAGE_TABLE_SHIFT
    mov ecx, ebx
    mov ebx, ebp
    cmp dword [esi+_process.stackpf], 0H
    js _page_fault_allocate ; stackpf = -1 mean stack page fault infinity
    jz _page_fault_segfault
    sub dword [esi+_process.stackpf], ecx
    js _page_fault_segfault
_page_fault_allocate:
    mov edx, edi
    xor eax, eax
    mov al, (_ALLOCATION_VIRTUAL or _ALLOCATION_HINT or _ALLOCATION_HOLE)
    call _map_virtual_address
    jnc _page_fault_exit
_page_fault_segfault:
    lea esi, [esp+4H]
    test byte [esi+_x86_register.error], _PF_US ; segfault happened in userspace ?
_page_fault_terminate:
    mov ebx, dword [_current]
    jz _segmentation_core
    xor eax, eax
    mov al, SIGSEGV
    call _send_signal
_page_fault_exit:
    ret

_switch_mapping_kernel:
    mov edx, dword [_kernel_mapping]
    jmp _switch_mapping
_switch_mapping_user:
    mov edx, dword [_current]
    mov edx, dword [edx+_process.mapping]
_switch_mapping:
 ; in: eax - new page directory
 ; out: zf - not set when page directory changed
 ; preserves: eax, ebx, ecx, esi, edi, ebp
 ; note:
 ;  this function must be called on each interrupt/syscall except amap, umap
 ;  this clear only the tlb when necessary and not PG page entry
 ;  use _flush_tlb instead if such result is desired
    push eax ebx
    mov eax, cr3
    mov ebx, edx
    cmp eax, ebx
    jz _switch_mapping_exit
    test byte [_singleton.pae], 1H
    jz _switch_mapping_reload
    cmp ebx, dword [_kernel_mapping] ; switch user to kernel
    jz _switch_mapping_reload
    push ebx
    call _pdpt_reserved
    mov ebx, dword [_kernel_mapping]
    call _pdpt_reserved
    pop ebx
_switch_mapping_reload:
    mov cr3, ebx
    test byte [_singleton.pae], 1H
    jz _switch_mapping_zero
    call _pdpt_read_write_current
_switch_mapping_zero:
    xor al, al
    cmp al, 1H
_switch_mapping_exit:
    pop ebx eax
    ret

_flush_tlb:
 ; in:
 ;  eax - virtual address to flush
 ;  ecx - count of virtual address to flush (if (<0H) flush all the tlb)
 ; preserves: ebx, edi, esi, ebp
 ; note: this function clear all the TLB even PG page entry except the page associated with the currently executed code
    test ecx, ecx
    jns _flush_tlb_mannual_loop
    test byte [_singleton.mtrr], 1H
    jz _flush_tlb_mannual
    mov ecx, _MTRR_CAP
    rdmsr
    test eax, _MTRR_CAP_FIX
    jz _flush_tlb_mannual
    mov ecx, _MTRR_DEF_TYPE
    rdmsr
    test eax, _MTRR_DEF_TYPE_FE
    jnz _flush_tlb_mtrr
    or eax, _MTRR_DEF_TYPE_FE
    wrmsr
_flush_tlb_mtrr:
    mov ecx, _MTRR_FIX_64K_00000
    rdmsr
    wrmsr
    ret
_flush_tlb_mannual:
    mov eax, cr3
    mov cr3, eax
    test byte [_singleton.pge], 1H
    jz _flush_tlb_mannual_exit
    mov ecx, _KERNEL_VIRTUAL_COUNT ; flush the global page also
    assert (_KERNEL_VIRTUAL_COUNT)
    mov eax, _KERNEL_VIRTUAL
_flush_tlb_mannual_loop:
    invlpg [eax]
    add eax, _PAGE_FRAME_SIZE
    loop _flush_tlb_mannual_loop
_flush_tlb_mannual_exit:
    ret

_is_power_two:
 ; in: eax - number to test out
 ; out:
 ;  edx - point to the bit position of the bit forward (-1 if eax = 0H)
 ;  ecx - point to the bit position of the bit backward (-1 if eax = 0H)
 ;   cf - set when eax is not a power of two
 ; preserves: eax, ebx, ebp, esi, edi 
    mov cl, (not 0H)
    movsx ecx, cl
    mov edx, ecx
    test eax, eax
    jz _power_two_carry
    bsf edx, eax
    bsr ecx, eax
    cmp ecx, edx
    jnz _power_two_carry
    ret
_power_two_carry:
    stc
    ret

_next_power_two:
 ; in: eax - target number
 ; out:
 ;  eax - the near power of two
 ;   cf - if the number is to large
 ; preserves: ebx, esi, edi, ebp
    call _is_power_two
    jnc _next_power_two_exit
    test ecx, ecx
    js _next_power_two_exit
    xor eax, eax
    mov al, 2H
    shl eax, cl
_next_power_two_exit:
    ret

irp _kind*, io,local
{
_#_kind#_apic_mtrr_set:
    xor eax, eax
    lea edx, [eax-1H]
    cmpxchg byte [_#_kind#_apic_mtrr_alloc], dl
    mov eax, _#_kind#_apic_mtrr_set_extract
    mov ebx, dword [_#_kind#_apic_base]
    mov ecx, _PAGE_FRAME_SIZE
    mov edx, _MTRR_TYPE_UC
    jnz _mark_memory_range_mtrr
    call _allocate_and_mark_memory_range_mtrr
    mov dword [_#_kind#_apic_mtrr_mask], ebx
    mov dword [_#_kind#_apic_mtrr_phys], ecx
    ret
_#_kind#_apic_mtrr_set_extract:
    mov ebx, dword [_#_kind#_apic_mtrr_mask]
    mov ecx, dword [_#_kind#_apic_mtrr_phys]
    ret
}

enum & _REFRESH_ONLY_IO_APIC
_refresh_apic_registers_set:
 ; in: eax - only refresh the io apic underlying address ?
 ; out: cf - set if refresh not worth (x2APIC enable, APIC disable or not present)
 ; preserves: ebx, ecx, ebp
 ; note: [_io_apic_base] is obtainable from either the ACPI table or MP table
    push ebx ecx
    cmp eax, (_REFRESH_ONLY_IO_APIC + 1H)
    cmc
    jc _refresh_apic_registers_set_exit
    test eax, eax
    jnz _refresh_apic_registers_set_io
    xor eax, eax
    mov al, _DEALLOCATION_VIRTUAL
    mov ebx, _PAE_LOCAL_APIC
    call _unmap_one_page_virtual_address
    jc _refresh_apic_registers_set_exit+1H
    test byte [_singleton.apic], 1H
    jz _refresh_apic_registers_set_exit
    xor ecx, ecx
    mov cl, _IA32_APIC_BASE
    rdmsr
    test eax, _APIC_BASE_EN
    jz _refresh_apic_registers_set_exit
    test eax, _APIC_BASE_EXTD
    jnz _refresh_apic_registers_set_exit
    and eax, (not _PAGE_OFFSET_MASK)
    mov dword [_local_apic_base], eax
    mov ebx, _frame
    xchg eax, ebx
    call _convert_linear_bitmap
    call _bitmap_set_to_reset
    jc _refresh_apic_registers_set_exit+1H
    call _local_apic_mtrr_set
    jc _refresh_apic_registers_set_exit+1H
    xor eax, eax
    mov al, (_ALLOCATION_VIRTUAL or _ALLOCATION_HINT)
    mov ebx, _PAE_LOCAL_APIC
    mov edx, _kernel_local_apic_base
    call _map_one_page_virtual_address
    jc _refresh_apic_registers_set_exit+1H
_refresh_apic_registers_set_io:
    cmp byte [_io_apic_count], 0H
    jz _refresh_apic_registers_set_exit+1H
    xor eax, eax
    mov al, _DEALLOCATION_VIRTUAL
    mov ebx, _PAE_IO_APIC
    call _unmap_one_page_virtual_address
    jc _refresh_apic_registers_set_exit+1H
    mov eax, _frame
    mov ebx, dword [_io_apic_base]
    xor edx, edx
    call _convert_linear_bitmap
    call _bitmap_set_to_reset
    jc _refresh_apic_registers_set_exit+1H
    call _io_apic_mtrr_set
    jc _refresh_apic_registers_set_exit+1H
    xor eax, eax
    mov al, (_ALLOCATION_VIRTUAL or _ALLOCATION_HINT)
    mov ebx, _PAE_IO_APIC
    mov edx, _kernel_io_apic_base
    call _map_one_page_virtual_address
    jmp _refresh_apic_registers_set_exit+1H
_refresh_apic_registers_set_exit:
    stc
    pop ecx ebx
    ret

_create_vdso:
 ; out: cf - set on error
 ; preserves: ebp
    xor eax, eax
    lea ecx, [eax+1H]
    test byte [_singleton.pae], 1H
    jz _create_vdso_allocate
    ;shl cl, 1H
    inc cl
_create_vdso_allocate:
    mov al, (_ALLOCATION_VIRTUAL or _ALLOCATION_PSE or _ALLOCATION_HINT)
    mov ebx, _USER_VDSO_VIRTUAL
    mov edx, _user_big_rw_page
    call _map_virtual_address
    jc _create_vdso_exit
    mov edi, ebx
    mov esi, _vdso_payload
    mov ecx, _vdso.sizeof
    call _copy_string
    call _linear_make_double_recursive
    mov esi, ebx
    mov edi, _kernel_vdso
    call _copy_entry
_create_vdso_exit:
    ret

_MIN_SLAB_OBJECT = 00020H
_MAX_SLAB_OBJECT = 20000H

_SLAB_METADATA = (_PAGE_FRAME_SIZE - _slab.sizeof)
_SLAB_BITMAP = ((_PAGE_FRAME_SIZE shr (bsf _MIN_SLAB_OBJECT)) shr 3H)
struct _slab _prev*, _next*, _page*, _start*, _cache*, _type*
    .list       _linked _prev, _next ; we place the linked list in the first address of the struct for _assign_list
    .cache:     dd (_cache) ; retreive information from slab object
    .page:      dd (_page) ; if the slab control is off the slab
    .start:     dd (_start) ; start of object
    .bitmap     _bitmap _SLAB_BITMAP
    .type:      db (_type)
    align       (_MIN_SLAB_OBJECT)
    .memory:
ends

_CACHE_POLICY = 020H ; max 020H empty slab in the empty table
_CACHE_STRING = 010H
_CACHE_THRESHOLD = (_PAGE_FRAME_SIZE shr 3H) ; 1H/8H
struct _cache _size*, _offslb*, _ctor*, _dtor*, _full*, _partial*, _empty*, _count*, _name*
    .size:      dd (_size) ; must be a power of two and (> 0H)
    .btscan:    db (0H)
    .offslb:    db (_offslb)
    .items:     dw (0H)
    .ctor:      dd (_ctor) ; argument in ebx, edi = cache, eax = function pointer
    .dtor:      dd (_dtor) ; argument in ebx, edi = cache, eax = function pointer
    .full:      dd (_full)
    .partial:   dd (_partial)
    .empty:     dd (_empty)
    .count:     dd (_count) ; how many object in the empty linked list
    .name       string _name
    times       (_CACHE_STRING - .name.sizeof) db 0H
ends

_slab_cache             _cache _slab.powertwo, 0H, _construct_slab, 0H, 0H, 0H, 0H, 0H, "OFF_SLAB"
_page_descriptor_cache  _cache _page_descriptor.powertwo, 0H, 0H, 0H, 0H, 0H, 0H, 0H, "PAGE_DESC"
_process_cache          _cache _process.powertwo, 0H, 0H, 0H, 0H, 0H, 0H, 0H, "PROCESS"
_process_group_cache    _cache _process_group_descriptor.powertwo, 0H, 0H, 0H, 0H, 0H, 0H, 0H, "PGROUP"
_session_cache          _cache _session_descriptor.powertwo, 0H, 0H, 0H, 0H, 0H, 0H, 0H, "SESSION"
_socket_cache           _cache _socket.powertwo, 0H, 0H, 0H, 0H, 0H, 0H, 0H, "SOCKET"

_frame_cache            _cache _x86_register.powertwo, 0H, _construct_frame, 0H, 0H, 0H, 0H, 0H, "FRAME"

; GPC (general purpose cache)
_mem_32_cache           _cache          _MIN_SLAB_OBJECT, 0H, 0H, 0H, 0H, 0H, 0H, 0H,   "MEM_32"
_mem_64_cache           _cache (_PAGE_FRAME_SIZE shr 6H), 0H, 0H, 0H, 0H, 0H, 0H, 0H,   "MEM_64"
_mem_128_cache          _cache (_PAGE_FRAME_SIZE shr 5H), 0H, 0H, 0H, 0H, 0H, 0H, 0H,  "MEM_128"
_mem_256_cache          _cache (_PAGE_FRAME_SIZE shr 4H), 0H, 0H, 0H, 0H, 0H, 0H, 0H,  "MEM_256"
_mem_512_cache          _cache (_PAGE_FRAME_SIZE shr 3H), 1H, 0H, 0H, 0H, 0H, 0H, 0H,  "MEM_512"
_mem_1K_cache           _cache (_PAGE_FRAME_SIZE shr 2H), 1H, 0H, 0H, 0H, 0H, 0H, 0H,   "MEM_1K"
_mem_2K_cache           _cache (_PAGE_FRAME_SIZE shr 1H), 1H, 0H, 0H, 0H, 0H, 0H, 0H,   "MEM_2K"
_mem_4K_cache           _cache          _PAGE_FRAME_SIZE, 1H, 0H, 0H, 0H, 0H, 0H, 0H,   "MEM_4K"
_mem_8K_cache           _cache (_PAGE_FRAME_SIZE shl 1H), 1H, 0H, 0H, 0H, 0H, 0H, 0H,   "MEM_8K"
_mem_16K_cache          _cache (_PAGE_FRAME_SIZE shl 2H), 1H, 0H, 0H, 0H, 0H, 0H, 0H,  "MEM_16K"
_mem_32K_cache          _cache (_PAGE_FRAME_SIZE shl 3H), 1H, 0H, 0H, 0H, 0H, 0H, 0H,  "MEM_32K"
_mem_64K_cache          _cache (_PAGE_FRAME_SIZE shl 4H), 1H, 0H, 0H, 0H, 0H, 0H, 0H,  "MEM_64K"
_mem_132K_cache         _cache          _MAX_SLAB_OBJECT, 1H, 0H, 0H, 0H, 0H, 0H, 0H, "MEM_132K"

_gpc_table:
    dd _mem_32_cache
    dd _mem_64_cache
    dd _mem_128_cache
    dd _mem_256_cache
    dd _mem_512_cache
    dd _mem_1K_cache
    dd _mem_2K_cache
    dd _mem_4K_cache
    dd _mem_8K_cache
    dd _mem_16K_cache
    dd _mem_32K_cache
    dd _mem_64K_cache
    dd _mem_132K_cache
_gpc_table_end:

_construct_slab:
 ; in: edi - cache object pointer
    pushad ; try to avoid this microcoded instruction but it's a single opcode
    xor ecx, ecx
    mov cl, _slab.list
    call _doubly_linked
    mov dword [ebx+_slab.cache], edi
    lea eax, [ebx+_slab.bitmap.table]   
    mov dword [ebx+_slab.bitmap.next], eax
    sub eax, _BITMAP_UNIT
    mov dword [ebx+_slab.bitmap.last], eax
    xor ecx, ecx
    mov dword [ebx+_slab.bitmap.free], ecx
    lea eax, [ebx+_slab.bitmap]
    mov ecx, _SLAB_BITMAP
    mov edi, _BITMAP_EXPAND_ZERO
    call _bitmap_resize
    popad
    ret

_construct_frame:
    ret

_cache_sanitize:
 ; in: edi - cache struct object
 ; out: cf - set on error
 ; preserves: ebx, edi, esi, ebp
    mov eax, [edi+_cache.size]
    call _is_power_two
    jc _cache_sanitize_exit
    mov ecx, _MIN_SLAB_OBJECT
    cmp eax, ecx
    cmovb eax, ecx
    jb _cache_sanitize_update
    mov ecx, _MAX_SLAB_OBJECT
    cmp eax, ecx
    jna _cache_sanitize_continue
    cmova eax, ecx
_cache_sanitize_update:
    mov dword [edi+_cache.size], eax
_cache_sanitize_continue:
    bsf edx, eax
    mov byte [edi+_cache.btscan], dl
    cmp eax, (_PAGE_FRAME_SIZE shr 3H)
    setae al
    mov byte [edi+_cache.offslb], al
    mov ecx, _PAGE_FRAME_SIZE
    mov eax, _SLAB_METADATA
    test byte [edi+_cache.offslb], 1H
    cmovnz eax, ecx
    movzx ecx, dl
    shr eax, cl
    setz cl
    add al, cl
    xor ah, ah
    mov word [edi+_cache.items], ax
_cache_sanitize_exit:
    ret

_allocate_from_cache:
 ; in:
 ;  eax - allocation kind type
 ;  edi - cache struct object
 ; out:
 ;  ebx - return allocated memory
 ;   cf - a problem has occured (either out of memory or cache slab are not consistent)
 ; preserves: edi, esi, ebp
    push esi ebp
    push 0H ; current list to update
    and al, _ALLOCATION_VIRTUAL
    mov esi, eax
    call _cache_sanitize
    jc _allocate_from_cache_exit
    lea eax, [edi+_cache.partial]
    lea ebx, [edi+_cache.empty]
    mov ebp, dword [eax]
    mov dword [esp], eax
    test ebp, ebp
    jnz _allocate_from_cache_reserve
    mov ebp, dword [ebx]
    mov dword [esp], ebx
    test ebp, ebp
    jnz _allocate_from_cache_reserve
    mov ebp, edi
    mov eax, esi
    mov ecx, dword [edi+_cache.size]
    _round_up ecx, _PAGE_FRAME_SIZE
    mov edx, _kernel_rw_page
    call _allocate_kernel_virtual
    mov edi, ebp
    jc _allocate_from_cache_exit
    mov ebp, ebx
    test byte [edi+_cache.offslb], 1H
    jnz _allocate_from_cache_control
    call _construct_slab
    mov byte [ebx+_slab.type], al
    lea eax, [ebx+_slab.memory]
_allocate_from_cache_register:
    mov dword [ebx+_slab.start], eax
    mov dword [ebx+_slab.page], ebp
    mov dword [edi+_cache.empty], ebx
    inc dword [edi+_cache.count]
    movzx edx, word [edi+_cache.items]
    mov ebp, ebx
    mov esi, edi
    mov edi, _BITMAP_SET
    lea eax, [ebx+_slab.bitmap]
    mov ecx, edx
    mov ebx, dword [eax+_bitmap.next]
    xor edx, edx
    call _bitmap_update
    mov edi, esi
    jc _allocate_from_cache_exit
    cmp edx, ecx
    stc
    jnz _allocate_from_cache_exit
    jmp _allocate_from_cache_search
_allocate_from_cache_control:
    mov esi, edi
    xor eax, eax
    mov al, _ALLOCATION_VIRTUAL
    mov edi, _slab_cache
    call _allocate_from_cache
    mov edi, esi
    jc _allocate_from_cache_exit
    mov byte [ebx+_slab.type], _ALLOCATION_VIRTUAL
    mov dword [ebx+_slab.cache], edi
    mov eax, ebp
    jmp _allocate_from_cache_register
_allocate_from_cache_reserve:
    lea eax, [ebp+_slab.bitmap]
_allocate_from_cache_search:
    xor ebx, ebx
    xor edx, edx
    xor ecx, ecx
    inc cl
    call _bitmap_search
    jc _allocate_from_cache_exit
    push edx
    mov esi, edi
    mov edi, _BITMAP_RESET
    call _bitmap_update
    mov edi, esi
    pop edx
    jc _allocate_from_cache_exit
    mov esi, dword [ebp+_slab.start]
    cmp dword [edi+_cache.size], _PAGE_FRAME_SIZE
    jae _allocate_from_cache_insert
    movzx ecx, byte [edi+_cache.btscan]
    add eax, _bitmap.sizeof
    sub ebx, eax
    lea ebx, [ebx*8H+edx]
    xor eax, eax
    inc al
    shl eax, cl
    dec eax
    mov edx, eax
    not eax
    shl ebx, cl
    add ebx, esi
    add ebx, edx
    and ebx, eax ; the get the object aligned with it's size (does not overlap with the slab header when it's in slab)
    mov esi, ebx
_allocate_from_cache_insert:
    lea ebx, [edi+_cache.empty]
    cmp dword [ebp+_slab.bitmap.free], 0H
    jnz _allocate_from_cache_change
    lea edx, [edi+_cache.full]   
    jmp _allocate_from_cache_list
_allocate_from_cache_change:
    lea edx, [edi+_cache.partial]
_allocate_from_cache_list:
    mov eax, dword [esp]
    cmp eax, edx ; when partial -> partial
    jz _allocate_from_cache_construct
    cmp eax, ebx ; check if origin is empty
    jnz _allocate_from_cache_assign
    dec dword [edi+_cache.count]
_allocate_from_cache_assign:
    call _assign_list
_allocate_from_cache_construct:
    mov ebx, esi
    mov eax, dword [edi+_cache.ctor]
    test eax, eax
    jz _allocate_from_cache_exit
    call eax
    clc 
_allocate_from_cache_exit:
    lea esp, [esp+4H]
    pop ebp esi
    ret

_deallocate_from_cache:
 ; in:
 ;  esi - object pointer
 ;  edi - cache struct object
 ; out: cf - set when the object not in the cache
 ; preserves: esi, edi, ebp
    push esi ebp
    push 0H ; list where the object resiee
    call _cache_sanitize
    jc _deallocate_from_cache_exit
    call _object_belong_cache
    jc _deallocate_from_cache_exit
    mov dword [esp], eax
    mov ebp, ebx
    mov eax, dword [edi+_cache.dtor]
    test eax, eax
    jz _deallocate_from_cache_bitmap
    mov ebx, esi
    call eax
_deallocate_from_cache_bitmap:
    mov eax, esi
    mov ecx, dword [ebp+_slab.start]
    sub eax, ecx
    jc _deallocate_from_cache_exit
    movzx ecx, byte [edi+_cache.btscan]
    shr eax, cl
    xor edx, edx
    mov dl, ((_BITMAP_UNIT shl 3H) - 1H)
    and edx, eax
    shr eax, 3H
    and al, (not (_BITMAP_UNIT - 1H))
    mov ebx, eax
    lea eax, [ebp+_slab.bitmap]
    lea ebx, [ebx+eax+_bitmap.table]
    xor ecx, ecx
    inc cl
    push edi
    mov edi, _BITMAP_RESET
    call _bitmap_inverse
    pop edi
    jc _deallocate_from_cache_exit
    movzx ecx, word [edi+_cache.items] 
    cmp dword [eax+_bitmap.free], ecx
    clc
    jnz _deallocate_from_cache_exit
    xor ecx, ecx
    lea edx, [edi+_cache.empty]
    mov eax, dword [edi+_cache.count]
    inc eax
    assert (_CACHE_POLICY)
    cmp eax, _CACHE_POLICY
    cmovae edx, ecx
    mov eax, dword [esp]
    call _assign_list
    jc _deallocate_from_cache_exit
    jz _deallocate_from_cache_slot
    inc dword [edi+_cache.count]
    jmp _deallocate_from_cache_exit
_deallocate_from_cache_slot:
    movzx eax, byte [ebp+_slab.type]
    mov ebx, dword [ebp+_slab.page]
    mov ecx, dword [edi+_cache.size]
    call _unmap_virtual_address
    jc _deallocate_from_cache_exit
    test byte [edi+_cache.offslb], 1H
    jz _deallocate_from_cache_exit
    mov esi, ebp
    mov edi, _slab_cache
    call _deallocate_from_cache
_deallocate_from_cache_exit:
    pop eax ebp esi
    ret

_retreive_gpc:  
 ; in: esi - pointer object
 ; out:
 ;  edi - cache struct object (0H if cf = 1H)
 ;  ebx - slab which contain the object
 ;   cf - set when none cache has been found
 ; preserves: esi, ebp
    push ebp
    mov ebp, _gpc_table
    assert (_gpc_table <> _gpc_table_end)
_retreive_gpc_loop:
    mov edi, dword [ebp]
    call _object_belong_cache
    jnc _retreive_gpc_exit
    add ebp, 4H
    cmp ebp, _gpc_table_end
    jb _retreive_gpc_loop
    xor edi, edi
    stc
_retreive_gpc_exit:
    pop ebp
    ret

_POTENTIAL_CACHE = 2H
_object_belong_cache:
 ; in:
 ;  esi - pointer object
 ;  edi - cache struct object
 ; out:
 ;  eax - list object pointer
 ;  ebx - slab which contain the object
 ;   cf - set when the object is not in the slab
 ; preserves: esi, edi, ebp
    push esi edi ebp
    mov ebp, esi
    and ebp, (not _PAGE_OFFSET_MASK)
    lea eax, [edi+_cache.full]
    lea ebx, [edi+_cache.partial]
    push eax ebx
    xor edi, edi
_object_belong_cache_loop:
    mov eax, dword [esp+edi*4H]
    mov ecx, _slab.list
    xor edx, edx
    mov dl, _LIST_FORWARD
    mov esi, _object_belong_cache_predicate
    call _find_list
    jnc _object_belong_cache_exit
    inc edi
    cmp edi, _POTENTIAL_CACHE
    jb _object_belong_cache_loop
    stc
_object_belong_cache_exit:
    pop ecx ecx ebp edi esi
    ret
_object_belong_cache_predicate:
    cmp dword [ebx+_slab.page], ebp
    jmp _convert_zero_carry

_doubly_linked:
 ; in:
 ;  ebx - doubly linked list
 ;  ecx - offset of the list in the struct (like offsetof)
 ; preserves: eax, ebx (ecx = 0H), ecx, edx, esi, edi, ebp
    add ebx, ecx
    mov dword [ebx+_linked.next], ebx
    mov dword [ebx+_linked.prev], ebx
    ret

_assign_list_esp:
 ; note: remove the top most item on the stack
    lea eax, [esp+4H]
    call _assign_list
    ret 4H

_assign_list:
 ; in:
 ;  eax - list source pointer (eax and [eax] must not be null)
 ;  edx - list destination pointer (if edx = null, [eax] is deleted anyway from eax)
 ; out:
 ;  ebx - [eax]
 ;   cf - set when parameter eax = 0H or [eax] = 0H
 ;   zf - when cf = 0, set when the [eax] node have been deleted
 ; preserves: esi, edi, ebp
    push esi edi
    test eax, eax
    jz _assign_list_carry
    cmp dword [eax], 0H
    jz _assign_list_carry
    mov esi, eax
    mov edi, edx
    mov ebx, dword [esi]
    mov ecx, dword [ebx+_linked.prev]
    cmp ebx, ecx
    jz _assign_list_nullify
    cmp ebx, dword [ebx+_linked.next]
    jnz _assign_list_sibling
_assign_list_nullify:   
    cmp ecx, dword [ebx+_linked.next]
    jnz _assign_list_carry
    xor ecx, ecx
    jmp _assign_list_reset
_assign_list_sibling:
    mov eax, dword [ebx+_linked.next]
    mov dword [ecx+_linked.next], eax
    mov ecx, dword [ebx+_linked.next]
    mov eax, dword [ebx+_linked.prev]
    mov dword [ecx+_linked.prev], eax
_assign_list_reset:
    mov dword [esi], ecx
    xor ecx, ecx
    call _doubly_linked
    test edi, edi
    jz _assign_list_exit
    mov ecx, dword [edi]
    jecxz _assign_list_rebase
    mov eax, dword [ecx+_linked.prev]
    mov dword [ebx+_linked.next], ecx
    mov dword [ebx+_linked.prev], eax
    mov dword [ecx+_linked.prev], ebx
    mov dword [eax+_linked.next], ebx
_assign_list_rebase:
    mov dword [edi], ebx
    or edi, edi ; clear zf
_assign_list_exit:
    clc
    jmp _assign_list_carry+1H
_assign_list_carry:
    stc
    pop edi esi
    ret

_remove_list_entry:
 ; in:
 ;  ebx - list node entry (_linked object pointer)
 ;  edx - base pointer of the list
 ; out:
 ;  cf - set on error
 ;  zf - only relevant when cf = 0H, set indicate that the list base [edx] has been nullified
 ; preserves: edx, esi, edi, ebp
 ; note: _remove_list_entry assume that ebx IS IN the list
    push edx
    mov eax, edx
    xor edx, edx
    cmp ebx, dword [eax]
    jz _remove_list_entry_match
    push ebx
    call _assign_list_esp
    jmp _remove_list_entry_nullify
_remove_list_entry_match:
    call _assign_list
_remove_list_entry_nullify:
    pop edx
    jc _remove_list_entry_exit
    cmp dword [edx], 0H
_remove_list_entry_exit:
    ret

_FIND_LIST_REMAINS = (5H shl 2H)
_FIND_LIST_REMAINS_SAVE_ALL = (_FIND_LIST_REMAINS + _PUSHA_TOTAL)
enum _LIST_FORWARD, _LIST_BACKWARD, _LIST_SAVE_ALL
_LIST_SAVE_ALL_MASK = 100B
_find_list:
 ; in: 
 ;  eax - list object pointer (must not be null otherwise cf = 1H)
 ;  ecx - offset of the list in the struct (like offsetof)
 ;  edx - direction (forward, backward)
 ;  esi - predicate (parameters ebx,ebp,(remain stack) and must preserve all register, cf = 1 if item match)
 ;  ebp - passed as-in
 ; out:
 ;  eax - list object pointer ([eax] = ebx)
 ;  ebx - target list node
 ;   cf - parameter are ill formed or item not found
 ; preserves: ecx, edi, esi, ebp
    push ecx edi
    push 0H ; last item in the double linked list
    mov ecx, edi
    test eax, eax
    jz _find_list_carry
;_def: XXX
    mov edi, dword [eax]
    test edi, edi
    jz _find_list_carry
    mov dword [esp], edi
    cmp edx, (_LIST_FORWARD or _LIST_BACKWARD or _LIST_SAVE_ALL)
    ja _find_list_carry
    mov edx, dword [_find_list_table+edx*4H]
_find_list_loop:
    mov ebx, edi
    sub ebx, dword [esp+8H]
    test dl, _LIST_SAVE_ALL_MASK
    jz _find_list_functor
    pusha
    call esi
    popa
    jmp _find_list_functor+2H
_find_list_functor:
    call esi
    cmc
    jnc _find_list_carry+1H
    call edx
_find_list_ensure:
    mov edi, dword [eax]
    cmp edi, dword [esp]
    jnz _find_list_loop
_find_list_carry:
    stc
    lea esp, [esp+4H]
    pop edi ecx
    ret
_find_list_table:
    dd _find_list_forward
    dd _find_list_backward
    dd _find_list_forward_save_all
    dd _find_list_backward_save_all
irp _kind*, forward,backward
{
    while (~($ and _LIST_SAVE_ALL_MASK))
        db 0H
    end while
    _find_list_#_kind#_save_all:
        nop [eax+07FH]
    _find_list_#_kind:
    match =forward, _kind \{ lea eax, [edi+_linked.next] \}
    match =backward, _kind \{ lea eax, [edi+_linked.prev] \}
        ret
}

_kmalloc:
    xor ebx, ebx
    jmp _common_malloc
_vmalloc:
    xor ebx, ebx
    mov bl, _ALLOCATION_VIRTUAL
_common_malloc:
 ; in:
 ;  eax - size of the target block
 ;  ebx - allocation type
 ; out:
 ;  eax - the requested pointer (0H when cf = 1H)
 ;   cf - error occurred
 ; preserves: edi, esi, ebp
    push edi
    call _next_power_two
    mov ecx, _MIN_SLAB_OBJECT
    cmp eax, ecx
    cmovb eax, ecx
    cmp eax, _MAX_SLAB_OBJECT
    ja _common_malloc_carry
    shr eax, (bsf _MIN_SLAB_OBJECT)
    bsf eax, eax
    mov edi, dword [_gpc_table+eax*4H]
    mov eax, dword [edi+_cache.name]
    mov eax, ebx
    call _allocate_from_cache
    mov eax, ebx
    jnc _common_malloc_exit
_common_malloc_carry:
    xor eax, eax
    stc
_common_malloc_exit:
    pop edi
    ret

_kfree:
_vfree:
 ; in: eax - pointer object
 ; out: cf - set when object not found in the cache
 ; preserves: esi, edi, ebp
    push esi edi
    mov esi, eax
    call _retreive_gpc
    jc _vfree_exit
    call _deallocate_from_cache
_vfree_exit:
    pop edi esi
    ret

_ksize:
_vsize:
 ; in: eax - pointer object
 ; out:
 ;  eax - pointer object size
 ;   cf - set when the source of the object is unknown
 ; preserves: esi, ebp
 ; note: the size returned may be not equal to the size used for the [kv]malloc
    push esi edi
    mov esi, eax
    call _retreive_gpc
    jc _vsize_exit
    mov eax, dword [edi+_cache.size]
_vsize_exit:
    pop edi esi
    ret

_reclaim_pid:
 ; out:
 ;  eax - fresh pid
 ;   cf - set when no pid has been found
 ; preserves: edi, esi, ebp
    push edi esi
    mov eax, _pid_table
    mov ebx, dword [_pid_table.next]
    xor ecx, ecx
    mov edx, ecx
    inc cl
    call _bitmap_search
    jc _reclaim_pid_exit
    lea esi, [ebx-_pid_table.table]
    shl esi, 3H
    add esi, edx
    mov edi, _BITMAP_RESET
    call _bitmap_update
    mov eax, esi
_reclaim_pid_exit:
    pop esi edi
    ret

_return_pid:
 ; in: eax - pid to free
 ; out: cf - set when pid already free
 ; preserves: edi, esi, ebp
    push edi
    mov edx, (_BITMAP_UNIT - 1H)
    and edx, eax
    shr eax, 3H
    and al, (not 011B)
    lea ebx, [_pid_table.table+eax]
    mov eax, _pid_table
    mov edi, _BITMAP_RESET
    xor ecx, ecx
    inc cl
    call _bitmap_inverse
    pop edi
    ret

enum & _SEARCH_ALIVE_SYSTEM, _SEARCH_ZOMBIE_SYSTEM, _SEARCH_ALIVE_CHILD, _SEARCH_ZOMBIE_CHILD
_search_pid:
 ; in:
 ;  eax - target pid
 ;  edx - search pattern
 ; out:
 ;  eax - list object pointer ([eax] = ebx)
 ;  ebx - target process
 ;   cf - set when no process has been found
 ; preserves: esi, edi, ebp
    push esi ebp
    test edx, edx
    jz _search_pid_carry
    cmp edx, (_SEARCH_ALIVE_SYSTEM or _SEARCH_ZOMBIE_SYSTEM or _SEARCH_ALIVE_CHILD or _SEARCH_ZOMBIE_CHILD)
    ja _search_pid_carry
    mov ebp, eax
    test dl, (_SEARCH_ALIVE_CHILD or _SEARCH_ZOMBIE_CHILD)
    mov eax, _process_list
    mov ecx, _process.list
    jz _search_pid_perform
    test dl, (_SEARCH_ALIVE_SYSTEM or _SEARCH_ZOMBIE_SYSTEM)
    mov eax, dword [_current]
    lea eax, [eax+_process.childs]
    mov ecx, _process.siblings
    jnz _search_pid_carry
    shr dl, 2H
_search_pid_perform:
    mov esi, dword [_search_pid_table+edx*4H]
    xor edx, edx
    mov dl, _LIST_FORWARD
    call _find_list
    jmp _search_pid_carry+1H
_search_pid_carry:
    stc
    pop ebp esi
    ret
_search_pid_table:
    dd 0H
    dd _search_pid_alive
    dd _search_pid_zombie
    dd _search_pid_system
_search_pid_system:
    cmp dword [ebx+_process.state], _PROCESS_DEAD
    jz _invert_zero_carry
    cmp dword [ebx+_process.pid], ebp
    jmp _convert_zero_carry
irp _kind*, alive,zombie
{
    _search_pid_#_kind:
        cmp dword [ebx+_process.state], _PROCESS_ZOMBIE
        match =alive, _kind \{ jnz _search_pid_system \}
        match =zombie, _kind \{ jz _search_pid_system \}
        ret
}

_search_group:
 ; in: eax - target group pid
 ; out:
 ;  ebx - _process_group_descriptor object pointer
 ;   cf - set if none process group found
 ; preserves: esi, edi, ebp
    push esi ebp
    mov ebp, eax
    mov eax, _process_group
    mov ecx, _process_group_descriptor.list
    xor edx, edx
    mov dl, _LIST_FORWARD
    mov esi, _search_group_system
    call _find_list
    pop ebp esi
    ret
_search_group_system:
    cmp dword [ebx+_process_group_descriptor.pgid], ebp
    jmp _convert_zero_carry

_ITERATE_CHILD_REMAINS = (_FIND_LIST_REMAINS_SAVE_ALL + (4H shl 1H))
_process_iterate_childs:
 ; in:
 ;  ebx - process object pointer
 ;  esi - predicate to call on each child (must not set carry)
 ; out:
 ;  eax - if find, point to the target item
 ;   cf - set when all items were examined
 ; preserves: ebx, esi, edi, ebp
    push ebx
    lea eax, [ebx+_process.childs]
    xor ecx, ecx
    xor edx, edx
    mov cl, _process.siblings
    mov dl, (_LIST_FORWARD or _LIST_SAVE_ALL)
    call _find_list
    mov eax, ebx
    pop ebx
    ret

_sleep_channel:
 ; in: 
 ;  eax - channel (only relevant when process not stopped)
 ;  ebx - process object pointer
 ; preserves: esi, edi, ebp
    push edi
    cmp dword [ebx+_process.state], _PROCESS_STOP
    jz _sleep_channel_schedule
    mov dword [ebx+_process.channel], eax
    mov dword [ebx+_process.state], _PROCESS_SLEEP
_sleep_channel_schedule:
    call _reschedule
    pop edi
    ret

_wakeup_channel:
 ; in: eax - channel
 ; preserves: esi, edi, ebp
    push esi ebp
    cmp eax, _PROCESS_CHANNEL
    jz _wakeup_channel_finish
    mov ebp, eax
_wakeup_channel_loop:
    mov eax, _process_list
    mov ecx, _process.list
    xor edx, edx
    mov dl, _LIST_FORWARD
    mov esi, _wakeup_channel_predicate
    call _find_list
    jc _wakeup_channel_finish
    mov dword [ebx+_process.state], _PROCESS_RUN
    mov dword [ebx+_process.channel], _PROCESS_CHANNEL
    jmp _wakeup_channel_loop
_wakeup_channel_finish:
    pop ebp esi
    ret
_wakeup_channel_predicate:
    cmp dword [ebx+_process.state], _PROCESS_SLEEP
    jnz _wakeup_channel_predicate_exit
    cmp dword [ebx+_process.channel], ebp
_wakeup_channel_predicate_exit:
    jmp _convert_zero_carry

_schedule:
 ; note: if all process sleeping or zombie, force init to run
    sub esp, 8H
_schedule_loop:
    mov ebx, dword [_initproc]
    mov eax, dword [ebx+_process.priority]
    mov dword [esp], eax
    mov dword [esp+4H], ebx
    mov eax, _process_list
    mov ecx, _process.list
    xor edx, edx
    mov dl, _LIST_FORWARD
    mov esi, _schedule_candidate
    call _find_list
    mov edi, dword [esp+4H]
    mov dword [edi+_process.priority], 0H
    mov dword [edi+_process.state], _PROCESS_RUN
    call _switch_process
    jmp _schedule_loop
_schedule_candidate:
    xor ebp, ebp
    cmp ebx, dword [_scheduler]
    jz _schedule_candidate_exit
    cmp dword [ebx+_process.state], _PROCESS_RUN
    jnz _schedule_candidate_exit
    mov ebp, dword [ebx+_process.increment]
    inc ebp
    add ebp, dword [ebx+_process.priority]
    cmp ebp, dword [esp+_FIND_LIST_REMAINS]
    jbe _schedule_candidate_exit
    mov dword [esp+_FIND_LIST_REMAINS], ebp
    mov dword [esp+_FIND_LIST_REMAINS+4H], ebx
_schedule_candidate_exit:
    mov dword [ebx+_process.priority], ebp
    clc
    ret

_initialize_multitasking:
 ; out: cf - set if multitasking is not properly initialized
 ; preserves: esi, edi, ebp
    call _create_process
    jc _initialize_multitasking_exit
    mov dword [_scheduler], ebx
    mov eax, dword [ebx+_process.kstack]
    sub eax, 4H
    mov dword [eax], _schedule
    mov dword [ebx+_process.context], eax
    call _create_process
    jc _initialize_multitasking_exit
    mov dword [_initproc], ebx
    mov dword [_current], ebx
    pop eax ; get the return address
    mov esp, dword [ebx+_process.kstack]
    mov dword [_tss.esp0], esp
    push eax
    call _syscall_ssid
_initialize_multitasking_exit:
    ret

_create_process:
 ; out:
 ;  ebx - newly created process structure
 ;   cf - set when out of memory
 ; preserves: esi, edi, ebp
    push esi edi
    xor eax, eax
    mov al, _ALLOCATION_VIRTUAL
    mov edi, _process_cache
    call _allocate_from_cache
    jc _create_process_exit
    mov esi, ebx
    mov edi, ebx
    mov ecx, _process.sizeof
    call _clear_string
    mov dword [esi+_process.socket], eax
    mov byte [esi+_process.fltctx.active], al
    mov byte [esi+_process.dbgctx.active], al
    mov byte [esi+_process.align], al
 irp _kind*, sigmask,pending,ports
 {
    lea eax, [esi+_process.#_kind]
    xor ebx, ebx
  if ((_kind) eq ports)
    mov ecx, _PORT_RANGE
    mov bl, _BITMAP_EXPAND_ONE
  else
    xor ecx, ecx
    mov bl, _BITMAP_EXPAND_ZERO
    mov cl, _PROCESS_SIGNALS_BITMAP
  end if
    call _bitmap_init
 }
    mov dword [esi+_process.uid], _ROOT_UID
    mov dword [esi+_process.stackpf], _PROCESS_STACKPF
    mov byte [esi+_process.intprec], _TPR_LOWEST
    mov eax, dword [esi+_process.pending]
    call _reclaim_pid
    jc _create_process_exit
    mov dword [esi+_process.pid], eax
    mov dword [esi+_process.sid], eax
    mov dword [esi+_process.pgid], eax
    mov dword [esi+_process.tid], eax
    mov ebx, esi
    mov ecx, _process.pgroup
    call _doubly_linked
    mov byte [esi+_process.refresh], (not 0H)

    ;xor eax, eax
    ;mov dword [esi+_process.increment], eax
    ;mov byte [esi+_process.daemon], al

    ;mov eax, dword [_current_teletype]
    ;mov dword [esi+_process.tty], eax
    ;mov ebx, esi
    ;mov ecx, _process.fground
    ;call _doubly_linked
    ;push ebx
    ;lea edx, dword [eax+_teletype.attach]
    ;call _assign_list_esp

    mov eax, _PAGE_FRAME_SIZE
    call _vmalloc
    jc _create_process_exit
    lea ebx, [eax+_PAGE_FRAME_SIZE]
    lea ecx, [ebx-_x86_register.sizeof]
    mov dword [esi+_process.pgstck], eax
    mov dword [esi+_process.kstack], ebx
    mov dword [esi+_process.retframe], ecx
    call _allocate_pdbr
    jc _create_process_exit
    mov dword [esi+_process.mapping], eax
    mov ebx, esi
    mov esi, eax
    call _default_mapping
    jc _create_process_exit
    mov ecx, _process.list
    call _doubly_linked
    push ebx
    mov edx, _process_list
    call _assign_list_esp
    sub ebx, _process.list
_create_process_exit:
    pop edi esi
    ret

_destroy_process:
 ; in: ebx - process structure object
 ; out: cf - set if allocation reported error
 ; note: XXX
    mov dword [ebx+_process.state], _PROCESS_DEAD
    ret

_reschedule:
    mov edi, dword [_scheduler]
_switch_process:
 ; in: edi - destination process
 ; preserves: esi, ebp
    push esi ebp
    push _switch_process_end
    mov esi, dword [_current]
    ;mov ebx, esi
    ;call _debug_save_register
    ;mov ebx, edi
    ;call _debug_export_register
    cmp byte [esi+_process.fltctx.active], 0H
    jz _switch_process_stack
    mov eax, dword [esi+_process.fltctx.save]
    fxsave [eax]
_switch_process_stack:
    mov eax, dword [edi+_process.kstack]
    mov dword [_tss.esp0], eax ; change entry for syscall
    xor eax, eax
    test byte [edi+_process.vm86], 1H
    jz _switch_process_save
    mov eax, dword [edi+_process.vstack]
_switch_process_save:
    mov dword [_tss_vm86.esp0], eax
    mov dword [_current], edi
    test byte [_singleton.apic], 1H
    jz _switch_process_change
    movzx eax, byte [edi+_process.intprec]
    mov dword [_PAE_LOCAL_APIC+_TASK_PRIORITY_REGISTER], eax
_switch_process_change:
    mov dword [esi+_process.context], esp
    mov esp, dword [edi+_process.context]
    mov ebx, edi
    call _express_alignement_mask
    call _set_cr0_ts
    jmp _switch_mapping_kernel
_switch_process_end:
    pop ebp esi
    ret

_set_cr0_ts:
 ; note: set CR0.TS to prevent usage of x87 of another process
    mov edx, _CR0_TS
    jmp _set_cr0

_express_alignement_mask:
 ; in: ebx - process struct pointer
 ; preserves: ebx, ecx, esi, edi, ebp
    push ebx
    mov eax, _clear_cr0_am
    cmp byte [ebx+_process.align], 0H
    jz _express_alignement_mask_invoke
    mov eax, _set_cr0_am
_express_alignement_mask_invoke:
    call eax
    pop ebx
    ret

_set_cr0_am:
 ; note: set CR0.AM for check unaligned access in user space (as well VM86)
    mov edx, _CR0_AM
    jmp _set_cr0

_clear_cr0_am:
    mov edx, _CR0_AM
    jmp _clear_cr0

irp _kind*, set,clear
{
_#_kind#_cr0:
 ; preserves: eax, ecx, edx, esi, edi, ebp
    call _pdpt_reserved_current
    mov eax, cr0
    match =set, _kind \{ or eax, edx \}
    match =clear, _kind
 \{
    not edx
    and eax, edx
    not edx
 \}
    mov cr0, eax
    call _pdpt_read_write_current
    ret
}

_save_floating_unit:
 ; in: eax - memory area to save information (x87 legacy FPU, SSE, AVX)
 ; out: cf - set if memory bad aligned
 ; preserves: ebx, ecx, esi, edi, ebp
    test byte [_singleton.sse], 1H
    jz _save_floating_unit_legacy
    test byte [_singleton.xsave], 1H
    jz _save_floating_unit_fxsave
    test byte [_singleton.avx], 1H
    jz _save_floating_unit_fxsave
    test eax, (040H - 1H)
    jnz _save_floating_unit_exit
    mov dword [_save_floating_unit_xsave], eax
    mov eax, (_XCR0_x87 or _XCR0_SSE or _XCR0_AVX)
    xor edx, edx
    xsave [0H]
  label _save_floating_unit_xsave dword at ($ - 4H)
    jmp _save_floating_unit_exit+1H
_save_floating_unit_fxsave:
    test eax, (010H - 1H)
    jnz _save_floating_unit_exit
    fxsave [eax]
    jmp _save_floating_unit_exit+1H
_save_floating_unit_legacy:
    fnstenv [eax]
    jmp _save_floating_unit_exit+1H
_save_floating_unit_exit:
    stc
    ret

_page_present:
 ; in: ebx - target page virtual address (only virtual address)
 ; out:
 ;  cf - set if not present
 ;  zf - only relevant if cf is clear, set to mean that a PSE page is targeted
 ; preserves: eax, ebx, ecx, edx, esi, edi, ebp
    push eax edx
    mov edx, ebx
    test byte [_singleton.pae], 1H
    jz _page_present_double
    call _linear_make_triple_recursive
    test dword [ebx], _PE_PRESENT
    mov ebx, edx
    jz _page_present_exit
_page_present_double:
    call _linear_make_double_recursive
    mov eax, ebx
    test dword [ebx], _PE_PRESENT
    mov ebx, edx
    jz _page_present_exit
    test dword [eax], _PDE_SIZE
    jz _page_present_single
    xor al, al
    jmp _page_present_exit-1H
_page_present_single:
    call _linear_make_single_recursive
    test dword [ebx], _PE_PRESENT
    mov ebx, edx
    jz _page_present_exit
    stc
_page_present_exit:
    cmc
    pop edx eax
    ret

_memory_accessible:
 ; in: ebx - target address
 ; out:
 ;  cf - set if not accessible by user (either kernel address or not present), or by kernel (not present)
 ;  zf - only relevant when cf = 0H, indicate that the target memory is a PSE page
 ; preserves: ebx, ecx, edx, esi, edi, ebp
 ; note: test only 1 page, useful to check if pointer function exist
    mov eax, dword [_current]
    cmp dword [eax+_process.pid], (_INIT_PID + 1H) ; only scheduler and init can access kernel memory
    assert (_SCHEDULER_PID < _INIT_PID)
    jc _memory_accessible_present
    call _memory_accessible_userspace
    jc _memory_accessible_exit
_memory_accessible_present:
    call _page_present
_memory_accessible_exit:
    ret
_memory_accessible_userspace:
    cmp ebx, _KERNEL_VIRTUAL
    cmc
    ret

_memories_accessible:
 ; in:
 ;  ebx - target address (low order 12-bit don't matter)
 ;  ecx - count of page to test for accessibility
 ; out: cf - set if not accessible by user (either kernel address or not present), or by kernel (not present)
 ; preserves: edx, esi, edi, ebp
    push edx
    clc
    jecxz _memories_accessible_exit
_memories_accessible_loop:
    call _memory_accessible
    jc _memories_accessible_exit
    jz _memories_accessible_pse
    add ebx, _PAGE_FRAME_SIZE
    loop _memories_accessible_loop
    jmp _memories_accessible_exit
_memories_accessible_pse:
    mov eax, ebx
    shr eax, _PAGE_TABLE_SHIFT
    xor edx, edx
    inc dl
    shl edx, ((bsf _PAE_TABLE_ENTRY_COUNT) + _PAGE_TABLE_SHIFT)
    test byte [_singleton.pae], 1H
    jnz _memories_accessible_dec
    shl edx, 1H
_memories_accessible_dec:
    dec edx
    or ebx, edx
    inc ebx
    mov edx, ebx
    shr edx, _PAGE_TABLE_SHIFT
    sub edx, eax
    sub ecx, edx
    ja _memories_accessible_loop
    stc
_memories_accessible_exit:
    pop edx
    ret

_userspace_sanitize:
 ; in:
 ;  ebx - userspace address
 ;  ecx - count of byte of the buffer
 ; out: cf - userspace not accessible
 ; preserves: edx, esi, edi, ebp
    jecxz _userspace_sanitize_check
    lea eax, [ebx+ecx]
    cmp eax, ebx ; overflow ? 
    jbe _userspace_sanitize_check
    test eax, _PAGE_OFFSET_MASK
    jnz _userspace_sanitize_compare
    dec eax
_userspace_sanitize_compare:
    and ebx, (not _PAGE_OFFSET_MASK)
    and eax, (not _PAGE_OFFSET_MASK)
    mov ecx, eax
    sub ecx, ebx
    shr ecx, _PAGE_TABLE_SHIFT
    inc ecx
_userspace_sanitize_check:
    call _memories_accessible
    ret

_nothing:
 ; note: function pointer that do nothing
    ret

_debug_intercept DT_gte _DE_PRESENT or _DPL0 or _386_INTERRUPT_GATE, 0H, _CODE_KERNEL, _panic_int1
_panic_color string\
    _ESCAPE, _ESCAPE_CHANGE_BACKGROUND, "04",\
    _ESCAPE, _ESCAPE_CHANGE_FOREGROUND, "0F"
_panic_header string "=== KERNEL PANIC ===", 00AH
_panic_string:
db "EAX:"
_panic_eax: db 8H dup 020H
db 020H, 020H, "EBX:"
_panic_ebx: db 8H dup 020H
db 020H, 020H, "ECX:"
_panic_ecx: db 8H dup 020H
db 020H, 020H, "EDX:"
_panic_edx: db 8H dup 020H
db 00AH, "ESI:"
_panic_esi: db 8H dup 020H
db 020H, 020H, "EDI:"
_panic_edi: db 8H dup 020H
db 020H, 020H, "ESP:"
_panic_esp: db 8H dup 020H
db 020H, 020H, "EBP:"
_panic_ebp: db 8H dup 020H
db 00AH, 020H, "CS:"
_panic_cs: db 8H dup 020H
db 020H, 020H, 020H, "DS:"
_panic_ds: db 8H dup 020H
db 020H, 020H, 020H, "SS:"
_panic_ss: db 8H dup 020H
db 020H, 020H, 020H, "ES:"
_panic_es: db 8H dup 020H
db 00AH, 020H, "FS:"
_panic_fs: db 8H dup 020H
db 020H, 020H, 020H, "GS:"
_panic_gs: db 8H dup 020H
db 020H, "LDTR:"
_panic_ldtr: db 8H dup 020H
db 020H, 020H, 020H, "TR:"
_panic_tr: db 8H dup 020H
db 00AH, "CR0:"
_panic_cr0: db 8H dup 020H
db 020H, 020H, "CR2:"
_panic_cr2: db 8H dup 020H
db 020H, 020H, "CR3:"
_panic_cr3: db 8H dup 020H
db 020H, 020H, "CR4:"
_panic_cr4: db 8H dup 020H
db 00AH, "DR0:"
_panic_dr0: db 8H dup 020H
db 020H, 020H, "DR1:"
_panic_dr1: db 8H dup 020H
db 020H, 020H, "DR2:"
_panic_dr2: db 8H dup 020H
db 020H, 020H, "DR3:"
_panic_dr3: db 8H dup 020H
db 00AH, "DR6:"
_panic_dr6: db 8H dup 020H
db 020H, 020H, "DR7:"
_panic_dr7: db 8H dup 020H
db 020H, "EFER:"
_panic_efer: db 8H dup 020H
db 020H, 020H, "EFL:"
_panic_efl: db 8H dup 020H, 00AH
_panic_string_end:
_panic_press string "Press any key to reboot ..."
_panic:
    pushf
    cli
    pusha
    mov edx, dword [esp+_PUSHA_EAX]
    mov edi, _panic_eax
    call _itoa_hexadecimal
    mov edx, dword [esp+_PUSHA_EBX]
    mov edi, _panic_ebx
    call _itoa_hexadecimal
    mov edx, dword [esp+_PUSHA_ECX]
    mov edi, _panic_ecx
    call _itoa_hexadecimal
    mov edx, dword [esp+_PUSHA_EDX]
    mov edi, _panic_edx
    call _itoa_hexadecimal
    mov edx, dword [esp+_PUSHA_ESI]
    mov edi, _panic_esi
    call _itoa_hexadecimal
    mov edx, dword [esp+_PUSHA_EDI]
    mov edi, _panic_edi
    call _itoa_hexadecimal
    mov edx, dword [esp+_PUSHA_EBP]
    mov edi, _panic_ebp
    call _itoa_hexadecimal
    mov edx, dword [esp+_PUSHA_ESP]
    mov edi, _panic_esp
    call _itoa_hexadecimal
    popa
    mov edx, cs
    mov edi, _panic_cs
    call _itoa_hexadecimal
    mov edx, ds
    mov edi, _panic_ds
    call _itoa_hexadecimal
    mov edx, ss
    mov edi, _panic_ss
    call _itoa_hexadecimal
    mov edx, es
    mov edi, _panic_es
    call _itoa_hexadecimal
    mov edx, fs
    mov edi, _panic_fs
    call _itoa_hexadecimal
    mov edx, gs
    mov edi, _panic_gs
    call _itoa_hexadecimal
    sldt edx
    mov edi, _panic_ldtr
    call _itoa_hexadecimal
    str edx
    mov edi, _panic_tr
    call _itoa_hexadecimal
    mov edx, cr0
    mov edi, _panic_cr0
    call _itoa_hexadecimal
    mov edx, cr2
    mov edi, _panic_cr2
    call _itoa_hexadecimal
    mov edx, cr3
    mov edi, _panic_cr3
    call _itoa_hexadecimal
    mov edx, cr4
    mov edi, _panic_cr4
    call _itoa_hexadecimal
    mov esi, _debug_intercept
    mov edi, (_IDT + _vector_1)
 rept 2H { movsd }
    ;mov word [_IDT+8H+0H], (_panic_int1 and 0FFFFH)
    ;mov word [_IDT+8H+6H], ((_panic_int1 shr 010H) and 0FFFFH)
    xor eax, eax
    mov edx, dr7
    or edx, eax
    mov edi, _panic_dr7
    call _itoa_hexadecimal
    mov edx, dr6
    mov edi, _panic_dr6
    call _itoa_hexadecimal
    mov edx, dr0
    mov edi, _panic_dr0
    call _itoa_hexadecimal
    mov edx, dr1
    mov edi, _panic_dr1
    call _itoa_hexadecimal
    mov edx, dr2
    mov edi, _panic_dr2
    call _itoa_hexadecimal
    mov edx, dr3
    mov edi, _panic_dr3
    call _itoa_hexadecimal
    mov ecx, _EFER
    rdmsr
    mov edx, eax
    mov edi, _panic_efer
    call _itoa_hexadecimal
    pop edx
    mov edi, _panic_efl
    call _itoa_hexadecimal
    mov ebx, dword [_current_teletype]
    mov esi, _panic_color
    mov ecx, _panic_color.sizeof
    call _teletype_write_string
    mov esi, _panic_header
    mov ecx, _panic_header.sizeof
    call _teletype_write_string
    mov esi, _panic_string
    mov ecx, (_panic_string_end - _panic_string)
    call _teletype_write_string
    mov esi, _panic_press
    mov ecx, _panic_press.sizeof
    call _teletype_write_string
_panic_loop:
    call _keyboard_driver
    jc _panic_loop
    jmp _reboot_system
_panic_int1:
    mov eax, _DR7_GD
    iretd

_itoa_hexadecimal:
 ; in:
 ;  edx - number
 ;  edi - address to store the representation
 ; preserves: ebx, esi, ebp
    std
    xor ecx, ecx
    mov cl, 8H
    lea edi, [edi+ecx-1H]
_itoa_hexadecimal_loop:
    mov al, dl
    and al, 00FH
    shr edx, 4H
    add al, 030H
    cmp al, 039H
    jbe _itoa_hexadecimal_store
    add al, 7H
_itoa_hexadecimal_store:
    stosb
    loop _itoa_hexadecimal_loop
    cld
    ret

include "errno.inc"

enum    _SYSCALL_EXIT, _SYSCALL_FORK, _SYSCALL_READ, _SYSCALL_WRITE, _SYSCALL_WAITPID, _SYSCALL_WAIT, _SYSCALL_EXEC, _SYSCALL_GUID, _SYSCALL_SUID,\
        _SYSCALL_BRK, _SYSCALL_AMAP, _SYSCALL_UMAP, _SYSCALL_MPROT, _SYSCALL_GPID, _SYSCALL_GPPID, _SYSCALL_GTID, _SYSCALL_UNAME, _SYSCALL_IOCTL,\
        _SYSCALL_SIGNAL, _SYSCALL_SIGRET, _SYSCALL_SIGMASK, _SYSCALL_KILL, _SYSCALL_RENICE, _SYSCALL_REBOOT, _SYSCALL_DAEMON, _SYSCALL_GPGID,\
        _SYSCALL_SPGID, _SYSCALL_GPGRP, _SYSCALL_SPGRP, _SYSCALL_GSID, _SYSCALL_SSID, _SYSCALL_ARGCPY, _SYSCALL_MACCESS, _SYSCALL_OPEN,\
        _SYSCALL_BIND, _SYSCALL_UNBIND, _SYSCALL_LISTEN, _SYSCALL_ALIVE, _SYSCALL_SEND, _SYSCALL_RECEIVE, _SYSCALL_FSHSCK,\
        _SYSCALL_CLOSE, _SYSCALL_CLSALL, _SYSCALL_MD5, _SYSCALL_SHA1, _SYSCALL_AESENC_ECB, _SYSCALL_ALIGN, _SYSCALL_TEST

_syscall_dispatcher:
 ; in:
 ;  eax - syscall number
 ;  ebx - 1th parameter
 ;  ecx - 2th parameter
 ;  edx - 3th parameter
 ;  esi - 4th parameter
 ;  edi - 5th parameter
 ;  ebp - 6th parameter
    shl eax, 2H
    cmp eax, (_syscall_dispatcher_table_end - _syscall_dispatcher_table)
    jae _syscall_dispatcher_exit
    call dword [_syscall_dispatcher_table+eax]
    jmp _syscall_dispatcher_exit+5H
_syscall_dispatcher_exit:
    mov eax, (-ENOSYS)
    ret
_syscall_dispatcher_table:
    dd _syscall_exit
    dd _syscall_fork
    dd _syscall_read
    dd _syscall_write
    dd _syscall_waitpid
    dd _syscall_wait
    dd _syscall_exec
    dd _syscall_guid
    dd _syscall_suid
    dd _syscall_brk
    dd _syscall_amap
    dd _syscall_umap
    dd _syscall_mprot
    dd _syscall_gpid
    dd _syscall_gppid
    dd _syscall_gtid
    dd _syscall_uname
    dd _syscall_ioctl
    dd _syscall_signal
    dd _syscall_sigret
    dd _syscall_sigmask
    dd _syscall_kill
    dd _syscall_renice
    dd _syscall_reboot
    dd _syscall_daemon
    dd _syscall_gpgid
    dd _syscall_spgid
    dd _syscall_gpgrp ; POSIX.1
    dd _syscall_spgrp ; Sytem V
    dd _syscall_gsid
    dd _syscall_ssid
    dd _syscall_argcpy
    dd _syscall_maccess
    dd _syscall_open
    dd _syscall_bind
    dd _syscall_unbind
    dd _syscall_listen
    dd _syscall_alive
    dd _syscall_send
    dd _syscall_receive
    dd _syscall_fshsck
    dd _syscall_close
    dd _syscall_clsall
    dd _syscall_md5
    dd _syscall_sha1

    dd _syscall_aesenc_ecb
    ;dd _syscall_aesdec
    dd _syscall_align
    dd _syscall_test
_syscall_dispatcher_table_end:

struct _winsize _ws_row*, _ws_col*, _ws_xpixel*, _ws_ypixel*
    .ws_row:    dw (_ws_row)
    .ws_col:    dw (_ws_col)
    .ws_xpixel: dw (_ws_xpixel)
    .ws_ypixel: dw (_ws_ypixel)
ends

enum    TCGETS, TCSETS, TCSETSF, TIOCGWINSZ, TIOCSWINSZ, FIONREAD, TIOCINQ:&, TCFLSH, TIOCSTI, TIOCSCTTY, TIOCNOTTY,\
        TIOCGPGRP, TIOCSPGRP, TIOCGSID, TIOCGTTYID, TIOCGWTTYID, _IOCTL:&
_syscall_ioctl:
 ; in:
 ;  ebx - tty number
 ;  ecx - ioctl command
 ;  edx - ioctl data
 ; note: in-predicate ioctl calling convention
 ;  ebx - teletype object pointer
 ;  ecx - size of data needed
 ;  edx - userspace memory region
 ;  ebp - [_current]
    cmp ecx, TIOCGWTTYID
    jz _syscall_ioctl_perform
    mov eax, (-EINVAL)
    call _retreive_teletype
    jc _syscall_write_exit
_syscall_ioctl_perform:
    cmp ecx, _IOCTL
    ja _syscall_ioctl_exit
    mov esi, ebx
    mov edi, ecx
    mov ecx, dword [_syscall_ioctl_table_size+ecx*4H]
    mov ebp, ecx
    mov ebx, edx
    call _userspace_sanitize
    mov eax, (-EFAULT)
    jc _syscall_ioctl_exit
    mov ebx, esi
    mov ecx, ebp
    mov ebp, dword [_current]
    call dword [_syscall_ioctl_table+edi*4H]
_syscall_ioctl_exit:
    ret
_syscall_ioctl_table:
    dd _syscall_ioctl_tcgets
    dd _syscall_ioctl_tcsets
    dd _syscall_ioctl_tcsetsf
    dd _syscall_ioctl_tiocgwinsz
    dd _syscall_ioctl_tiocswinsz
    dd _syscall_ioctl_tiocinq
    dd _syscall_ioctl_tcflsh
    dd _syscall_ioctl_tiocsti
    dd _syscall_ioctl_tiocsctty
    dd _syscall_ioctl_tiocnotty
    dd _syscall_ioctl_tiocgpgrp
    dd _syscall_ioctl_tiocspgrp
    dd _syscall_ioctl_tiocgsid
    dd _syscall_ioctl_tiocgttyid
    dd _syscall_ioctl_tiocgwttyid
_syscall_ioctl_table_end:
assert ((((_syscall_ioctl_table_end - _syscall_ioctl_table) shr 2H) - 1H) = _IOCTL)
_syscall_ioctl_table_size:
    dd _termios.sizeof
    dd _termios.sizeof
    dd _termios.sizeof
    dd _winsize.sizeof
    dd _winsize.sizeof
    dd 4H
    dd 0H
    dd 1H
    dd 0H
    dd 0H
    dd 4H
    dd 4H
    dd 4H
    dd 4H
    dd 4H
_syscall_ioctl_table_size_end:
assert ((((_syscall_ioctl_table_size_end - _syscall_ioctl_table_size) shr 2H) - 1H) = _IOCTL)
_syscall_ioctl_tcgets:
 ; note: everyone can read termios of whatever teletype
    xor eax, eax
    lea esi, [ebx+_teletype.termios]
    mov edi, edx
    jmp _copy_string
_syscall_ioctl_tcsetsf:
    call _syscall_ioctl_tcflsh
    jc _syscall_ioctl_tcsets_exit
    jmp _syscall_ioctl_tcsets_prepare
_syscall_ioctl_tcsets:
    call _teletype_controlling
    mov eax, (-EPERM)
    jc _syscall_ioctl_tcsets_exit
    mov ebp, edx
_syscall_ioctl_tcsets_prepare:
    mov esi, ebp
    xor eax, eax
    mov al, _SEND_SIGTTOU
    call _process_foreground_group_current
    mov eax, (-ENOTTY)
    jc _syscall_ioctl_tcsets_exit
    cmp byte [ebx+_teletype.eoi], 0H
    jz _syscall_ioctl_tcsets_copy
    test byte [esi+_termios.lflag], ICANON
    jnz _syscall_ioctl_tcsets_copy
    call _teletype_reset_canonical
_syscall_ioctl_tcsets_copy:
    lea edi, [ebx+_teletype.termios]
    xor ecx, ecx
    mov cl, _termios.sizeof
    call _copy_string
    xor eax, eax
_syscall_ioctl_tcsets_exit:
    ret

_syscall_ioctl_tiocgwinsz:
    mov ax, word [ebx+_teletype.ygrid]
    mov word [edx+_winsize.ws_row], ax
    mov ax, word [ebx+_teletype.xgrid]
    mov word [edx+_winsize.ws_col], ax
    mov ax, word [_current_modeinfo.x_resolution]
    mov word [edx+_winsize.ws_xpixel], ax
    mov ax, word [_current_modeinfo.y_resolution]
    mov word [edx+_winsize.ws_ypixel], ax
    xor eax, eax
    ret
_syscall_ioctl_tiocswinsz:
    cmp dword [ebp+_process.uid], _ROOT_UID
    mov eax, (-EPERM)
    jnz _syscall_ioctl_tiocswinsz_exit
    movzx eax, word [edx+_winsize.ws_xpixel]
    movzx ecx, word [edx+_winsize.ws_ypixel]
    mov edx, ecx
    mov cl, byte [ebx+_teletype.legacy]
    mov byte [ebx+_teletype.legacy], 0H
    cmp eax, _TELETYPE_GRAPHIC_320x200_WIDTH
    jnz _syscall_ioctl_tiocswinsz_search
    cmp edx, _TELETYPE_GRAPHIC_320x200_HEIGHT
    jnz _syscall_ioctl_tiocswinsz_search
    mov byte [ebx+_teletype.legacy], (not 0H)
    test cl, cl
    jnz _syscall_ioctl_tiocswinsz_legacy
    xor eax, eax
    mov al, _CONVERT_RGB_VGA
    call _teletype_switch_color
_syscall_ioctl_tiocswinsz_legacy:
    mov ax, _TELETYPE_GRAPHIC_320x200_RESOLUTION
    call _video_bios
    mov eax, (-EFAULT)
    jc _syscall_ioctl_tiocswinsz_exit
    mov word [_current_modeinfo.bytes_scanline], _TELETYPE_GRAPHIC_320x200_SCANLINE
    mov word [_current_modeinfo.x_resolution], _TELETYPE_GRAPHIC_320x200_WIDTH
    mov word [_current_modeinfo.y_resolution], _TELETYPE_GRAPHIC_320x200_HEIGHT
    mov dword [_current_modeinfo.physical], _TELETYPE_GRAPHIC_320x200_VIDEO
    mov byte [_current_modeinfo.bits_pixel], _TELETYPE_GRAPHIC_320x200_PITCH
    jmp _syscall_ioctl_tiocswinsz_refresh
_syscall_ioctl_tiocswinsz_search:
    test cl, cl
    jz _syscall_ioctl_tiocswinsz_vesa
    xor eax, eax
    mov al, _CONVERT_VGA_RGB
    call _teletype_switch_color
_syscall_ioctl_tiocswinsz_vesa:
    call _search_vbe_mode
    mov eax, (-EFAULT)
    jc _syscall_ioctl_tiocswinsz_exit
    mov eax, (-ESRCH)
    js _syscall_ioctl_tiocswinsz_exit
_syscall_ioctl_tiocswinsz_refresh:
    call _refresh_resolution
    mov eax, (-ENOMEM)
    jc _syscall_ioctl_tiocswinsz_exit
    xor eax, eax
_syscall_ioctl_tiocswinsz_exit:
    ret

_syscall_ioctl_tiocinq:
    movzx eax, word [ebx+_teletype.index]
    mov dword [edx], eax
    xor eax, eax
    ret

_syscall_ioctl_tcflsh:
 ; out:
 ;  ebp = edx used by _syscall_ioctl_tcsetsf
 ;   cf - set when has no enough right
    call _teletype_controlling
    mov eax, (-EPERM)
    jc _syscall_ioctl_tiocgsid_exit
    mov edi, dword [ebx+_teletype.input]
    mov ebp, edx
    xor ecx, ecx
    inc cl
    call _clear_pages
    mov word [ebx+_teletype.index], ax
    call _teletype_reset_canonical
_syscall_ioctl_tcflsh_exit:
    ret

_syscall_ioctl_tiocsti:
    call _teletype_controlling
    mov eax, (-EPERM)
    jc _syscall_ioctl_tiocsti
    movzx eax, byte [edx]
    call _keyboard_irq_send
    xor eax, eax
_syscall_ioctl_tiocsti_exit:
    ret

_syscall_ioctl_tiocsctty:
 ; note:
 ;  set the tty (ebx) the controlling terminal of the current session. Can be called if the current is either a session leader or a root process
 ;  normally ecx = 0H in this function
    call _teletype_controlling
    mov eax, (-EPERM)
    jo _syscall_ioctl_tiocsctty_root
    js _syscall_ioctl_tiocsctty_sanitize
    jc _syscall_ioctl_tiocsctty_exit
    jmp _syscall_ioctl_tiocsctty_exit-2H
_syscall_ioctl_tiocsctty_sanitize:
    cmp byte [ebp+_process.seslead], 0H
    jz _syscall_ioctl_tiocsctty_exit
    cmp byte [ebx+_teletype.control], 0H
    jnz _syscall_ioctl_tiocsctty_exit
_syscall_ioctl_tiocsctty_root:
    mov byte [esi+_session_descriptor.attach], (not 0H)
    mov dword [esi+_session_descriptor.teletype], ebx
    mov byte [ebx+_teletype.control], (not 0H)
    mov byte [ebx+_teletype.fground], cl
    mov dword [ebx+_teletype.sesdesc], esi
    mov dword [ebx+_teletype.grpdesc], ecx
    xor eax, eax
_syscall_ioctl_tiocsctty_exit:
    ret

_syscall_ioctl_tiocnotty:
 ; note:
 ;  a process can detatch the controlling terminal of a session either if it's root or the session leader of this terminal
 ;  normally ecx = 0H in this function
    call _teletype_controlling
    mov eax, (-EPERM)
    jo _syscall_ioctl_tiocnotty_root
    js _syscall_ioctl_tiocsctty_exit-2H
    jc _syscall_ioctl_tiocnotty_exit
    cmp byte [ebp+_process.seslead], 0H
    jz _syscall_ioctl_tiocnotty_exit
    jmp _syscall_ioctl_tiocnotty_dettach
_syscall_ioctl_tiocnotty_root:
    cmp ebx, dword [esi+_session_descriptor.teletype]
    jnz _syscall_ioctl_tiocnotty_free
_syscall_ioctl_tiocnotty_dettach:
    mov byte [esi+_session_descriptor.attach], cl
    mov dword [esi+_session_descriptor.teletype], ecx
_syscall_ioctl_tiocnotty_free:
    mov byte [ebx+_teletype.control], cl
    mov dword [ebx+_teletype.sesdesc], ecx
    mov edx, dword [ebx+_teletype.grpdesc]
    mov dword [ebx+_teletype.grpdesc], ecx
    cmp byte [ebx+_teletype.fground], cl
    mov byte [ebx+_teletype.fground], cl
    jz _syscall_ioctl_tiocnotty_exit-2H
    mov ebx, edx
    mov eax, SIGHUP
    call _send_signal_process_group
    mov eax, SIGCONT
    call _send_signal_process_group
    xor eax, eax
_syscall_ioctl_tiocnotty_exit:
    ret

_syscall_ioctl_tiocgpgrp:
 ; note: only root or process of the same session can retreive the pgid of the foreground process group
    call _teletype_controlling
    mov eax, (-EPERM)
    jc _syscall_ioctl_tiocgpgrp_exit
    cmp dword [ebx+_teletype.fground], 0H
    mov eax, (-EEXIST)
    jz _syscall_ioctl_tiocgpgrp_exit
    mov ebx, dword [ebx+_teletype.grpdesc]
    mov ebx, dword [ebx+_process_group_descriptor.pgid]
    mov dword [edx], ebx
    xor eax, eax
_syscall_ioctl_tiocgpgrp_exit:
    ret

_syscall_ioctl_tiocspgrp:
 ; note: only root or the teletype session leader can modify the foreground process group
    call _teletype_controlling
    mov eax, (-EPERM)
    jc _syscall_ioctl_tiocspgrp_exit
    jo _syscall_ioctl_tiocspgrp_perform
    cmp byte [ebp+_process.seslead], 0H
    jz _syscall_ioctl_tiocspgrp_exit
_syscall_ioctl_tiocspgrp_perform:
    mov edi, ebx
    mov eax, dword [edx]
    call _search_group
    mov eax, (-ESRCH)
    jc _syscall_ioctl_tiocspgrp_exit
    cmp dword [ebp+_process.uid], _ROOT_UID
    jz _syscall_ioctl_tiocspgrp_update
    ; XXX
    ;mov eax, dword [ebp+_process.sesdesc]
    ;cmp eax, dword [ebp+_process.sesleader]
_syscall_ioctl_tiocspgrp_update:
    mov dword [edi+_teletype.grpdesc], ebx
    mov byte [edi+_teletype.fground], (not 0H)
    xor eax, eax
_syscall_ioctl_tiocspgrp_exit:
    ret

_syscall_ioctl_tiocgsid:
 ; note: only root or a process in the same session can retreive the sid
    call _teletype_controlling
    mov eax, (-ENOTTY)
    jc _syscall_ioctl_tiocgsid_exit
    mov eax, dword [esi+_session_descriptor.sid]
    mov dword [edx], eax
    xor eax, eax
_syscall_ioctl_tiocgsid_exit:
    ret

_syscall_ioctl_tiocgwttyid:
    mov ebx, dword [_current_teletype]
_syscall_ioctl_tiocgttyid:
    movzx eax, byte [ebx+_teletype.id]
    mov dword [edx], eax
    xor eax, eax
_syscall_ioctl_tiocgttyid_exit:
    ret

_teletype_controlling:
 ; in:
 ;  ebx - teletype object pointer
 ;  ebp - process object pointer
 ; out: 
 ;  esi - session descriptor of the current process
 ;   of - set if root uid (cf = 0H)
 ;   sf - only when (cf = 1H) indicate that the process has no teletype attached
 ;   cf - set if the current teletype has no right to modify the target teletype
 ; preserves: ebx, ecx, edx, edi, ebp
    mov esi, dword [ebp+_process.sesdesc]
    cmp dword [ebp+_process.uid], _ROOT_UID
    jz _teletype_controlling_root
    cmp byte [esi+_session_descriptor.attach], 0H
    jz _teletype_controlling_attach
    cmp ebx, dword [esi+_session_descriptor.teletype]
    jz _teletype_controlling_exit
    stc
    jmp _teletype_controlling_exit
_teletype_controlling_root:
    mov eax, _EFLAGS_OF
    call _set_eflags
    jmp _teletype_controlling_exit
_teletype_controlling_attach:
    xor eax, eax
    mov al, (_EFLAGS_SF or _EFLAGS_CF)
    call _set_eflags
_teletype_controlling_exit:
    ret

_kernel_version string "achiu-au OS V5"
_UNAME_SIZE = 010H
_syscall_uname:
 ; in: ebx - userpace buffer (minmax _UNAME_SIZE)
 ; out: eax = size of the string written
    mov edi, ebx
    mov ecx, _UNAME_SIZE
    call _userspace_sanitize
    mov eax, (-EINVAL)
    jc _syscall_uname_exit
    mov esi, _kernel_version
    mov ecx, _kernel_version.sizeof
    mov eax, ecx
    call _copy_string
_syscall_uname_exit:
    ret

_TELETYPE_CURRENT = (not 0H)
_retreive_teletype:
 ; in: ebx - wanted teletype 
 ; out:
 ;  ebx - teletype object pointer
 ;   cf - set when id teletype > _TELETYPE_COUNT
 ; preserves: eax, ecx, edx, esi, edi, ebp
    test ebx, ebx
    jns _retreive_teletype_lookup
    mov ebx, dword [_current]   
    mov ebx, dword [ebx+_process.sesdesc]
    cmp byte [ebx+_session_descriptor.attach], 0H
    jz _retreive_teletype_exit
    mov ebx, dword [ebx+_session_descriptor.teletype]
    stc
    jmp _retreive_teletype_exit
_retreive_teletype_lookup:
    cmp ebx, _TELETYPE_COUNT
    jae _retreive_teletype_exit
    mov ebx, dword [_teletype_table+ebx*4H]
_retreive_teletype_exit:
    cmc
    ret

_REBOOT_MAGIC1 = 0FEE1DEADH
_REBOOT_MAGIC2 = 028121969H
_REBOOT_CMD_RESTART = 1234567H
_REBOOT_CMD_HALT = 0CDEF0123H
_syscall_reboot:
 ; in:
 ;  ebx - reboot magic 1H
 ;  ecx - reboot magic 2H
 ;  edx - command
    mov eax, (-EINVAL)
    mov esi, dword [_current]
    cmp dword [esi+_process.uid], _ROOT_UID
    jnz _syscall_reboot_exit
    cmp ebx, _REBOOT_MAGIC1
    jnz _syscall_reboot_exit
    cmp ecx, _REBOOT_MAGIC2
    jnz _syscall_reboot_exit
    mov ebx, _reboot_system
    cmp edx, _REBOOT_CMD_RESTART
    jz _syscall_reboot_jump
    mov ebx, _power_off
    cmp edx, _REBOOT_CMD_HALT
    jnz _syscall_reboot_exit
_syscall_reboot_jump:
    wbinvd
    jmp ebx
_syscall_reboot_exit:
    ret

_teletype_initialize:
 ; out: cf - set on error
    mov dword [_current_teletype], _tty1
    push _teletype_table ; teletype table list pointer
    push _TELETYPE_COUNT ; teletype counter
_teletype_initialize_loop:
    mov esi, dword [esp+4H]
    lodsd
    mov ebp, eax
    mov dword [esp+4H], esi
    xor eax, eax
    xor ecx, ecx
    mov al, _ALLOCATION_VIRTUAL
    inc cl
    mov edx, _kernel_rw_page
    call _allocate_kernel_virtual
    jc _teletype_initialize_exit
    mov dword [ebp+_teletype.input], ebx
    mov ebx, ebp
    xor ecx, ecx
    mov cl, TCSETSF
    mov edx, _default_termios
    call _syscall_ioctl_perform
    dec dword [esp]
    jnz _teletype_initialize_loop
    clc
_teletype_initialize_exit:
    lea esp, [esp+8H]
    ret

enum _TELETYPE_BEEP:7H, _TELETYPE_BACKSPACE, _TELETYPE_TABULATION:9H, _TELETYPE_NEWLINE, _TELETYPE_CARRIAGE:00DH
_ESCAPE_CLEAR = 043H
_ESCAPE_MOVE_UP = 05AH
_ESCAPE_MOVE_DOWN = 053H
_ESCAPE_MOVE_RIGHT = 051H
_ESCAPE_MOVE_LEFT = 044H
_ESCAPE_CHANGE_BACKGROUND = 042H
_ESCAPE_CHANGE_FOREGROUND = 046H
_ESCAPE_CURSOR_TOP_MOST = 04BH
_ESCAPE_DISABLE_CURSOR = 049H
_ESCAPE_ENABLE_CURSOR = 04CH
_ESCAPE_SAVE_CURSOR = 041H
_ESCAPE_RESTORE_CURSOR = 052H
_ESCAPE_CURSOR_POSITION = 048H
_ESCAPE_CURSOR_RECEIVE = 058H
_ESCAPE_CURSOR_RECEIVE_SIZE = (2H + (4H shl 1H) + 1H)
_teletype_write_string:
 ; in:
 ;  ebx - tty object pointer
 ;  esi - character string
 ;  ecx - string length
 ; out:
 ;  ecx - remain length
 ;   cf - set on error
 ; preserves: ebx, ebp
 ; note:
 ;  \eC - clear the whole screen
 ;  \eZ - move up the cursor
 ;  \eS - move down the cursor
 ;  \eQ - move right the cursor
 ;  \eD - mode left the cursor
 ;  \eB{hexdigit}{2} - change the background color
 ;  \eF{hexdigit}{2} - change the foreground color
 ;  \eK - set cursor to the top most position
 ;  \eI - disable cursor, hide it
 ;  \eL - enable cursor, show it
 ;  \eA - save the cursor position (original 0H,0H)
 ;  \eR - restore the cursor position
 ;  \eH - request position cursor
 ;  \eX{hexdigit}{4};{hexdigit}{4} - position cursor received (do not send in a write, must be in a read)
    push ebp
    xor ebp, ebp
    mov edi, _TELETYPE_UPDATE_CURSOR
    test ecx, ecx
    jz _teletype_write_string_exit
_teletype_write_string_loop:
    lodsb
    test ebp, ebp
    jz _teletype_write_string_escape
    cmp al, _ESCAPE_CLEAR
    jz _teletype_write_string_clear
    cmp al, _ESCAPE_MOVE_RIGHT
    jz _teletype_write_string_right
    cmp al, _ESCAPE_MOVE_LEFT
    jz _teletype_write_string_left
    cmp al, _ESCAPE_MOVE_UP
    jz _teletype_write_string_up
    cmp al, _ESCAPE_MOVE_DOWN
    jz _teletype_write_string_down
    cmp al, _ESCAPE_CHANGE_BACKGROUND
    jz _teletype_write_string_color
    cmp al, _ESCAPE_CHANGE_FOREGROUND
    jz _teletype_write_string_color
    cmp al, _ESCAPE_CURSOR_TOP_MOST
    jz _teletype_write_string_top_most
    cmp al, _ESCAPE_DISABLE_CURSOR
    jz _teletype_write_string_disable_cursor
    cmp al, _ESCAPE_ENABLE_CURSOR
    jz _teletype_write_string_enable_cursor
    cmp al, _ESCAPE_CURSOR_POSITION
    jz _teletype_write_string_cursor_position
    cmp al, _ESCAPE_SAVE_CURSOR
    jz _teletype_write_string_save
    cmp al, _ESCAPE_RESTORE_CURSOR
    jnz _teletype_write_string_reset+2H
    mov ebp, _teletype_write_string_restore
    call _teletype_update_cursor
    jmp _teletype_write_string_reset
_teletype_write_string_clear:
    call _teletype_clear
    jmp _teletype_write_string_reset
_teletype_write_string_right:
    mov ebp, _teletype_direction_forward
    call _teletype_update_cursor
    jmp _teletype_write_string_reset
_teletype_write_string_left:
    mov ebp, _teletype_direction_backward
    call _teletype_update_cursor
    jmp _teletype_write_string_reset
_teletype_write_string_up:
    mov ebp, _teletype_direction_upward
    call _teletype_update_cursor
    jmp _teletype_write_string_reset
_teletype_write_string_down:
    mov ebp, _teletype_direction_downward
    call _teletype_update_cursor
    jmp _teletype_write_string_reset
_teletype_write_string_top_most:    
    mov ebp, _teletype_direction_reset
    call _teletype_update_cursor
    jmp _teletype_write_string_reset
 irp _kind*, disable,enable
 {
_teletype_write_string_#_kind#_cursor:
    mov ebp, _teletype_write_string_trampoling
    match =disable, _kind
    \{
        call _teletype_update_cursor
        mov byte [ebx+_teletype.cursor], 0H
    \}
    match =enable, _kind
    \{
        mov byte [ebx+_teletype.cursor], (not 0H)
        call _teletype_update_cursor
    \}
    jmp _teletype_write_string_reset
 }
_teletype_write_string_cursor_position:
    push ecx edi
    mov al, _ESCAPE
    call _teletype_insert_character
    jc _teletype_write_string_cursor_position_reset
    mov al, _ESCAPE_CURSOR_RECEIVE
    call _teletype_insert_character
    jc _teletype_write_string_cursor_position_reset
    movzx edx, word [ebx+_teletype.ylinear]
    ror edx, 010H
    mov dx, word [ebx+_teletype.xlinear]
    xor ecx, ecx
    mov cl, (8H + 1H)
_teletype_write_string_cursor_position_loop:
    cmp cl, (4H + 1H)
    jnz _teletype_write_string_cursor_position_loop_convert
    mov al, 03BH
    call _teletype_insert_character
    jmp _teletype_write_string_cursor_position_loop_update
_teletype_write_string_cursor_position_loop_convert:
    mov edi, ebx
    mov ebx, _hexadecimal_table
    mov eax, edx
    and eax, 0F0000000H
    rol eax, 4H
    xlatb
    mov ebx, edi
    shl edx, 4H
    call _teletype_insert_character
_teletype_write_string_cursor_position_loop_update:
    jc _teletype_write_string_cursor_position_reset
    loop _teletype_write_string_cursor_position_loop
_teletype_write_string_cursor_position_reset:
    pop edi ecx
    jmp _teletype_write_string_reset+2H
_teletype_write_string_save:
    mov ax, word [ebx+_teletype.xlinear]
    mov word [ebx+_teletype.xsaved], ax
    mov ax, word [ebx+_teletype.ylinear]
    mov word [ebx+_teletype.ysaved], ax
    jmp _teletype_write_string_reset+2H
_teletype_write_string_color:
    cmp ecx, 2H
    jbe _teletype_write_string_reset+2H
    movzx edx, byte [esi]
    call _convert_ascii_hexadecimal
    jc _teletype_write_string_reset+2H
    shl edx, 8H
    mov dl, byte [esi+1H]
    call _convert_ascii_hexadecimal
    jc _teletype_write_string_reset+2H
    cmp edx, _MAX_COLOR
    jae _teletype_write_string_reset+2H
    add esi, 2H
    sub ecx, 2H
    mov ebp, _teletype_write_string_rgb_table
    cmp byte [ebx+_teletype.legacy], 0H
    jnz _teletype_write_string_legacy
    jmp $+7H
_teletype_write_string_legacy:
    mov ebp, _teletype_write_string_rgb_table
    mov edx, dword [ebp+edx*4H]
    cmp al, _ESCAPE_CHANGE_BACKGROUND ; carry can't be generated here
    jz _teletype_write_string_change
    mov dword [ebx+_teletype.foregnd], edx
    jmp _teletype_write_string_reset
_teletype_write_string_change:
    mov dword [ebx+_teletype.backgnd], edx
_teletype_write_string_reset:
    jc _teletype_write_string_exit
    xor ebp, ebp
    jmp _teletype_write_string_udpate+2H
_teletype_write_string_escape:
    cmp al, _ESCAPE
    jnz _teletype_write_string_display
    not ebp
    jmp _teletype_write_string_udpate+2H
_teletype_write_string_display:
    xor edx, edx
    cmp al, 07FH
    jae _teletype_write_string_udpate+2H
    call _teletype_write_character
_teletype_write_string_udpate:
    jc _teletype_write_string_exit
    dec ecx
    jnz _teletype_write_string_loop
_teletype_write_string_exit:
    pop ebp
    ret
_teletype_write_string_vga_table:
    dd _VGA_BLACK
    dd _VGA_BLUE
    dd _VGA_GREEN
    dd _VGA_CYAN
    dd _VGA_RED
    dd _VGA_MAGENTA
    dd _VGA_BROWN
    dd _VGA_LIGHT_GRAY
    dd _VGA_DARK_GRAY
    dd _VGA_LIGHT_BLUE
    dd _VGA_LIGHT_GREEN
    dd _VGA_LIGHT_CYAN
    dd _VGA_LIGHT_RED
    dd _VGA_LIGHT_MAGENTA
    dd _VGA_YELLOW
    dd _VGA_WHITE
_teletype_write_string_vga_table_end:
assert (((_teletype_write_string_vga_table_end - _teletype_write_string_vga_table) shr 2H) = _MAX_COLOR)
_teletype_write_string_rgb_table:
    dd _RGB_BLACK
    dd _RGB_BLUE
    dd _RGB_GREEN
    dd _RGB_CYAN
    dd _RGB_RED
    dd _RGB_MAGENTA
    dd _RGB_BROWN
    dd _RGB_LIGHT_GRAY
    dd _RGB_DARK_GRAY
    dd _RGB_LIGHT_BLUE
    dd _RGB_LIGHT_GREEN
    dd _RGB_LIGHT_CYAN
    dd _RGB_LIGHT_RED
    dd _RGB_LIGHT_MAGENTA
    dd _RGB_YELLOW
    dd _RGB_WHITE
_teletype_write_string_rgb_table_end:
assert (((_teletype_write_string_rgb_table_end - _teletype_write_string_rgb_table) shr 2H) = _MAX_COLOR)
_teletype_write_string_restore:
    mov ax, word [ebx+_teletype.xsaved]
    mov word [ebx+_teletype.xlinear], ax
    mov ax, word [ebx+_teletype.ysaved]
    mov word [ebx+_teletype.ylinear], ax
    ret
_teletype_write_string_trampoling:
    add dword [esp], 5H ; size of a call instruction with an immediate
    ret

_convert_ascii_hexadecimal:
 ; in: dl - ascii character
 ; out:
 ;  dl - hexadecimal value
 ;  cf - set if dl does not represent an hex digit
    sub dl, 030H
    jc _convert_ascii_hexadecimal_exit
    cmp dl, 00AH
    cmc
    jnc _convert_ascii_hexadecimal_exit
    and dl, (not 020H)
    sub dl, 011H
    jc _convert_ascii_hexadecimal_exit
    cmp dl, 6H
    cmc
    jc _convert_ascii_hexadecimal_exit
    add dl, 00AH
_convert_ascii_hexadecimal_exit:
    ret

_hexadecimal_table string "0123456789ABCDEF"

include "teletype.inc"

_bsf_bits_pixel:
 ; out: ecx - bsf of the _current_modeinfo.bits_pixel
 ; preserves: eax, ebx, edx, esi, edi, ebp
    mov cl, byte [_current_modeinfo.bits_pixel]
    shr cl, 3H
    bsf ecx, ecx
    ret

enum _VBE_CONTROLLER_INFORMATION, _VBE_MODE_INFORMATION, _VBE_SET_MODE
_vbe_video_bios:
    mov ah, 04FH
    call _video_bios
    jc _vbe_video_bios_exit
    cmp ax, 04FH
    jz _vbe_video_bios_exit
    stc
_vbe_video_bios_exit:
    ret

_VIDEO_MODE_END     = 0FFFFH
_VIDEO_MODE_WIDTH   = 2D0H
_VIDEO_MODE_HEIGHT  = 1E0H
_VIDEO_MODE_PITCH   = 020H
_search_vbe_mode:
 ; in:
 ;  eax - wanted video mode width
 ;  edx - wanted video mode height 
 ; out:
 ;  eax - new mode found
 ;   cf - set on error
 ;   sf - only relevent when cf = 0H, indicate that no mode have been found
    mul edx
    jc _search_vbe_mode_carry
    push eax        ; dimmension request
    push (not 0H)   ; difference of resolution
    push 0H         ; current mode
    call _addressing_real_current
    mov byte [ebx+_process.lckreal], (not 0H)
    mov al, _VBE_CONTROLLER_INFORMATION
    mov edi, _DATUM_UNREAL
    mov dword [edi+_vbe_info_block.signature], _VBE2_SIGNATURE
    call _vbe_video_bios
    jc _search_vbe_mode_support
    movzx eax, word [_DATUM_UNREAL+_vbe_info_block.video_mode]
    movzx ebx, word [_DATUM_UNREAL+_vbe_info_block.video_mode+2H]
    _real_segment ebx, ebx:eax
_search_vbe_mode_loop:
    cmp word [ebx], _VIDEO_MODE_END
    jz _search_vbe_mode_finish
    mov al, _VBE_MODE_INFORMATION
    movzx ecx, word [ebx]
    mov edi, (_DATUM_UNREAL+_vbe_info_block.sizeof)
    push ebx ecx edi
    call _vbe_video_bios
    pop edi ecx ebx
    jc _search_vbe_mode_carry+1H
    movzx eax, word [edi+_mode_info_block.mode_attributes]
    test al, _VBE_ATTRIBUTE_LINEAR
    jz _search_vbe_mode_update
    test al, _VBE_ATTRIBUTE_COLOR
    jz _search_vbe_mode_update
    mov al, byte [edi+_mode_info_block.memory_model]
    cmp al, _VBE_MEMORY_MODEL_PACKED
    jz _search_vbe_mode_next
    cmp al, _VBE_MEMORY_MODEL_DIRECT
    jnz _search_vbe_mode_update
_search_vbe_mode_next:
    cmp byte [edi+_mode_info_block.bits_pixel], _VIDEO_MODE_PITCH
    jnz _search_vbe_mode_update
    movzx eax, word [edi+_mode_info_block.x_resolution]
    movzx edx, word [edi+_mode_info_block.y_resolution]
    mul edx
    jc _search_vbe_mode_update
    sub eax, dword [esp+8H]
    jns _search_vbe_mode_revert
    neg eax
_search_vbe_mode_revert:
    cmp eax, dword [esp+4H]
    ja _search_vbe_mode_update
    mov dword [esp+4H], eax
    mov dword [esp], ecx
_search_vbe_mode_update:
    add ebx, 2H
    jmp _search_vbe_mode_loop
_search_vbe_mode_finish:
    mov ebx, dword [_current]
    mov byte [ebx+_process.lckreal], 0H
    call _addressing_real_revert ; XXX

    cmp dword [esp], 0H
    jnz _search_vbe_mode_install
_search_vbe_mode_support:
    xor eax, eax
    mov al, _EFLAGS_SF
    call _set_eflags   
    jmp _search_vbe_mode_carry+1H
_search_vbe_mode_install:
    mov al, _VBE_MODE_INFORMATION
    mov ecx, dword [esp]
    mov edi, (_DATUM_UNREAL+_vbe_info_block.sizeof)
    push edi
    call _vbe_video_bios
    pop esi
    jc _search_vbe_mode_carry+1H
    call _addressing_real_current ; XXX
    mov edi, _current_modeinfo
    mov ecx, _mode_info_block.sizeof
    call _copy_string
    mov ebx, dword [esp]
    or ebx, _VBE_ENABLE_FRAMEBUFFER
    mov al, _VBE_SET_MODE
    push ebx
    call _vbe_video_bios
    pop eax
    jmp _search_vbe_mode_carry+1H
_search_vbe_mode_carry:
    stc
    lea esp, [esp+00CH]
    ret

_REGEN_4MB_PAGE = 4H ; count of 4Mb page to be allocated for a frame buffer
_refresh_resolution:
 ; out: cf - set on error
 ; note: for the regen buffer, allocate page aligned to 4Mb byte using PSE
    push _teletype_table
    push _TELETYPE_COUNT
    movzx eax, word [_current_modeinfo.bytes_scanline]
    movzx ecx, word [_current_modeinfo.y_resolution]
    mul ecx
    jc _refresh_resolution_exit
    mov dword [_vbe_frame_amount], eax
    mov ecx, eax
    _align_up ecx, (1H shl _PAGE_DIRECTORY_SHIFT) ; align to a 4Mb boundary
    shr ecx, _PAGE_TABLE_SHIFT
    mov ebx, dword [_current_modeinfo.physical]
    and ebx, (not _PSE_OFFSET_MASK)
    cmp ebx, _MAX_REAL_ADDRESS
    jbe _refresh_resolution_page
    mov eax, _frame
    call _convert_linear_bitmap
    mov edi, _BITMAP_SET
    call _bitmap_inverse
    ;jc _refresh_resolution_exit ; XXX
_refresh_resolution_page:
    shr ecx, (_PAGE_DIRECTORY_SHIFT - _PAGE_TABLE_SHIFT)
    cmp ecx, (_REGEN_4MB_PAGE + 1H)
    cmc
    jc _refresh_resolution_exit
    mov eax, _process_list
    mov ecx, _process.list
    xor edx, edx
    mov dl, _LIST_FORWARD
    mov esi, _refresh_resolution_process
    call _find_list
    cmc
    jc _refresh_resolution_exit
    mov ebx, _FRAME_BUFFER_START
    test byte [_singleton.pae], 1H
    jz _refresh_resolution_video
    mov ebx, _PAE_FRAME_BUFFER_START
_refresh_resolution_video:
    mov eax, dword [_current_modeinfo.physical]
    and eax, _PSE_OFFSET_MASK
    lea ebp, [ebx+eax]
_refresh_resolution_loop:
    mov esi, dword [esp+4H]
    lodsd
    mov ebx, eax
    mov dword [esp+4H], esi
    mov dword [ebx+_teletype.video], ebp
    cmp byte [ebx+_teletype.vdfrbf], 0H
    jnz _refresh_resolution_font
    push ebx
    xor eax, eax
    mov al, (_ALLOCATION_VIRTUAL or _ALLOCATION_PSE)
    mov edx, _kernel_big_rw_page
    xor ecx, ecx
    mov cl, _REGEN_4MB_PAGE
    call _allocate_kernel_virtual
    mov eax, ebx
    pop ebx
    jc _refresh_resolution_exit
    mov dword [ebx+_teletype.regen], eax
    mov byte [ebx+_teletype.vdfrbf], (not 0H)
_refresh_resolution_font:
    mov esi, _default_font_8x16
    xor ecx, ecx
    mov cl, _SET_FONT_FORCE
    call _teletype_set_font
    jc _refresh_resolution_exit
    dec dword [esp]
    jnz _refresh_resolution_loop
_refresh_resolution_exit:
    lea esp, [esp+8H]
    ret
_refresh_resolution_process:
    mov byte [ebx+_process.refresh], (not 0H)
    ret

enum _CONVERT_VGA_RGB, _CONVERT_RGB_VGA
_convert_color:
 ; in:
 ;  eax - action to perform
 ;  edx - color
 ; out: eax - new color
 ; preserves: ebx, ecx, edx, esi, edi, ebp
    cmp eax, (_CONVERT_RGB_VGA + 1H)
    cmc
    jc _convert_color_exit
    cmp al, _CONVERT_VGA_RGB
    jz _convert_color_vga_rgb
    xor eax, eax
irp _kind*, BLACK,BLUE,GREEN,CYAN,RED,MAGENTA,BROWN,LIGHT_GRAY,DARK_GRAY,LIGHT_BLUE,LIGHT_GREEN,LIGHT_CYAN,LIGHT_RED,LIGHT_MAGENTA,YELLOW,WHITE
{
    cmp edx, _RGB_#_kind
    mov al, _VGA_#_kind
    jz _convert_color_exit
}
    jmp _convert_color_exit-1H
_convert_color_vga_rgb:
irp _kind*, BLACK,BLUE,GREEN,CYAN,RED,MAGENTA,BROWN,LIGHT_GRAY,DARK_GRAY,LIGHT_BLUE,LIGHT_GREEN,LIGHT_CYAN,LIGHT_RED,LIGHT_MAGENTA,YELLOW,WHITE
{
    cmp dl, _VGA_#_kind
    mov eax, _RGB_#_kind
    jz _convert_color_exit
}
    stc
_convert_color_exit:
    ret

_teletype_switch_color:
 ; in: 
 ;  eax - convert kind
 ;  ebx - teletype object pointer
 ; preserves: ebx, ecx, esi, edi, ebp
    push eax
    mov edx, dword [ebx+_teletype.foregnd]
    call _convert_color
    mov dword [ebx+_teletype.foregnd], eax
    pop eax
    mov edx, dword [ebx+_teletype.backgnd]
    call _convert_color
    mov dword [ebx+_teletype.backgnd], eax
    ret

_syscall_write:
 ; in:
 ;  ebx - tty number (-1H if current tty)
 ;  ecx - buffer to send
 ;  edx - size of buffer
    mov eax, (-EINVAL)
    call _retreive_teletype
    jc _syscall_write_exit
    test dword [ebx+_teletype.termios.lflag], TOSTOP
    jz _syscall_write_perform
    push ecx edx
    xor eax, eax
    mov al, _SEND_SIGTTOU
    call _process_foreground_group_current
    mov eax, (-ENOTTY)
    pop edx ecx
    jc _syscall_read_exit
_syscall_write_perform:
    mov esi, ecx
    mov ebp, dword [_current]
    cmp byte [ebp+_process.extsig], 0H ; if the process must exit because of a non handled signal
    mov ebp, edx
    jnz _syscall_write_bypass
    xchg ecx, edx
    jecxz _syscall_write_written
    xchg ebx, edx
    call _userspace_sanitize
    mov eax, (-EFAULT)
    jc _syscall_write_exit
    mov ebx, edx
_syscall_write_bypass:
    mov ecx, ebp
    call _teletype_write_string
    mov eax, (-EFAULT)
    jc _syscall_write_exit
_syscall_write_written:
    mov eax, ebp
    sub eax, ecx
_syscall_write_exit:
    ret

enum & _SEND_SIGTTIN, _SEND_SIGTTOU
_process_foreground_group_current:
    mov ebp, dword [_current]
_process_foreground_group:
 ; in:
 ;  eax - kind
 ;  ebx - teletype object pointer
 ;  ebp - process object pointer
 ; preserves: ebx, esi, edi, ebp
 ; note:
 ;  search process in the foreground group and send signal if it's not found
 ;  send sigttin, sigttou only of the process are in the same session of the terminal
    push ebx esi edi ebp
    mov edx, ebx
    xor ebx, ebx
    mov bl, (_SEND_SIGTTIN or _SEND_SIGTTOU)
    cmp eax, ebx
    ja _process_foreground_group_carry
    call _ensure_flags_exclusive
    jc _process_foreground_group_exit
    mov ebx, edx
    cmp byte [ebx+_teletype.control], 0H
    jz _process_foreground_group_exit
    cmp byte [ebx+_teletype.fground], 0H
    jz _process_foreground_group_send
    push ebx
    mov edi, eax
    mov eax, dword [ebx+_teletype.grpdesc]
    lea eax, [eax+_process_group_descriptor.prclist]
    xor ecx, ecx
    xor edx, edx
    mov cl, _process.pgroup
    mov dl, (_LIST_FORWARD or _LIST_SAVE_ALL)
    mov esi, _process_foreground_group_search
    call _find_list
    mov eax, edi
    pop ebx
    jnc _process_foreground_group_exit
_process_foreground_group_send:
    mov edx, dword [ebx+_teletype.sesdesc]
    cmp edx, dword [ebp+_process.sesdesc]
    clc
    jnz _process_foreground_group_exit
    mov edx, SIGTTOU
    test al, _SEND_SIGTTOU
    mov eax, SIGTTIN
    cmovz eax, edx
    mov ebx, ebp
    call _send_signal
_process_foreground_group_carry:
    stc
_process_foreground_group_exit:
    pop ebp edi esi eax
    ret
_process_foreground_group_search:
    cmp ebp, ebx
    jmp _convert_zero_carry

_syscall_open:
 ; out: eax - socket filde
    mov esi, dword [_current]
    cmp dword [esi+_process.sockno], 07FFFFFFFH
    mov eax, (-ERANGE)
    jz _syscall_open_exit
    xor eax, eax
    mov al, _ALLOCATION_VIRTUAL
    mov edi, _socket_cache
    call _allocate_from_cache
    mov eax, (-ENOMEM)
    jc _syscall_open_exit
    xor eax, eax
    mov byte [ebx+_socket.lock], al
    mov byte [ebx+_socket.bind], al
    mov word [ebx+_socket.port], ax
    mov edi, dword [esi+_process.sockno]
    mov dword [ebx+_socket.filde], edi
    mov ecx, _socket.list
    call _doubly_linked
    push ebx
    lea edx, [esi+_process.socket]    
    call _assign_list_esp
    inc dword [esi+_process.sockno]
    mov eax, edi
_syscall_open_exit:
    ret

_convert_port_bitmap:
 ; in:
 ;  eax - bitmap object pointer
 ;  ecx - port number
 ; out: cf - carry set if data erroneous
    call _sanitize_port_number
    jc _convert_port_bitmap_exit
    mov edx, ecx
    and edx, 01FH
    mov ebx, ecx
    shr ebx, 3H
    and ebx, (not 011B)
    lea ebx, [eax+_bitmap.table+ebx]
_convert_port_bitmap_exit:
    ret

_sanitize_port_number:
 ; in: ecx - port number
 ; out: cf - set if port number is invalid
    cmp ecx, _PORT_AVAILABLE
    cmc
    ret

_syscall_bind:
 ; in:
 ;  ebx - socket number
 ;  ecx - port number
    mov esi, ecx
    mov ebp, dword [_current]
    mov eax, ebx
    mov ebx, ebp
    xor edx, edx
    mov dl, _SOCKET_FILDE
    call _process_find_socket
    mov eax, (-EFAULT)
    jc _syscall_bind_exit
    cmp byte [ebx+_socket.bind], 0H
    mov eax, (-EBUSY)
    jnz _syscall_bind_exit
    lea eax, [ebp+_process.ports]
    mov ebp, ebx
    mov ecx, esi
    call _convert_port_bitmap
    jnc _syscall_bind_switch
    mov eax, (-EINVAL)
    jmp _syscall_bind_exit
_syscall_bind_switch:
    xor ecx, ecx
    inc cl
    mov edi, _BITMAP_SET
    call _bitmap_inverse
    mov eax, (-EBUSY)
    jc _syscall_bind_exit
    mov byte [ebp+_socket.bind], (not 0H)
    mov word [ebp+_socket.port], si
    xor eax, eax
_syscall_bind_exit:
    ret

_syscall_listen:
 ; in: ebx - socket port number
    mov eax, ebx
    mov esi, dword [_current]
    mov ebx, esi
    xor edx, edx
    mov dl, _SOCKET_PORT
    call _process_find_socket
    mov eax, (-EEXIST)
    jc _syscall_listen_exit
    cmp byte [ebx+_socket.lock], 0H
    jnz _syscall_listen_exit-2H
    mov eax, ebx
    mov ebx, esi
    call _sleep_channel
    xor eax, eax
_syscall_listen_exit:
    ret

enum _SOCKET_FILDE, _SOCKET_PORT
_process_find_socket:
 ; in:
 ;  eax - socket number or port number (assume port number is valid)
 ;  ebx - target process
 ;  edx - search kind
 ; out:
 ;  ebx - socket structure pointer
 ;   cf - set if no socket has been found 
 ; preserves: esi, edi, ebp
    cmp edx, (_SOCKET_PORT + 1H)
    cmc
    jc _process_find_socket_exit
    push esi ebp
    mov ebp, eax
    mov eax, dword [ebx+_process.socket]
    mov ecx, _socket.list
    mov esi, dword [_process_find_socket_table+edx*4H]
    xor edx, edx
    mov dl, _LIST_FORWARD
    call _find_list
    pop ebp esi
_process_find_socket_exit:
    ret
_process_find_socket_table:
    dd _process_find_socket_filde
    dd _process_find_socket_port
_process_find_socket_filde:
    cmp dword [ebx+_socket.filde], ebp
    jmp _convert_zero_carry
_process_find_socket_port:
    cmp byte [ebx+_socket.bind], 0H
    jz _invert_zero_carry
    cmp word [ebx+_socket.port], bp
    jmp _convert_zero_carry

_syscall_alive:
 ; in:
 ;  ebx - target process pid
 ;  ecx - socket port number
 ; out: cf - set when not alive
    mov esi, ecx
    call _sanitize_port_number
    mov eax, (-EINVAL)
    jc _syscall_alive_exit
    mov eax, ebx
    xor edx, edx
    mov dl, _SEARCH_ALIVE_SYSTEM
    call _search_pid
    mov eax, (-EEXIST)
    jc _syscall_send_finish
    mov eax, esi
    xor edx, edx
    mov dl, _SOCKET_PORT
    call _process_find_socket
    mov eax, (-ENOENT)
    jc _syscall_send_finish
    xor eax, eax
_syscall_alive_exit:
    ret

_syscall_send:
 ; in:
 ;  ebx - target process pid
 ;  ecx - socket port number
 ;  edx - userspace buffer
 ;  esi - userspace buffer size
 ; out: eax - written data count
    push esi
    call _syscall_gpid
    cmp eax, ebx
    mov eax, (-EINVAL)
    jz _syscall_send_finish
    call _sanitize_port_number
    jc _syscall_send_finish
    xchg esi, ecx
    jecxz _syscall_send_copy
    mov edi, edx
    xchg ebx, edx
    call _userspace_sanitize
    mov eax, (-EACCES)
    jc _syscall_send_finish
    mov eax, edx
    xor edx, edx
    mov dl, _SEARCH_ALIVE_SYSTEM
    call _search_pid
    mov eax, (-EEXIST)
    jc _syscall_send_finish
    mov eax, esi
    xor edx, edx
    mov dl, _SOCKET_PORT
    call _process_find_socket
    mov eax, (-ENOENT)
    jc _syscall_send_finish
    mov ebp, ebx
    mov eax, ebx
    call _wakeup_channel
    mov ebx, ebp
    xor edx, edx
    mov eax, edx
    lea ecx, [edx-1H]
    lock cmpxchg byte [ebx+_socket.lock], cl
    mov eax, (-EBUSY)
    jnz _syscall_send_finish
    mov dword [ebx+_socket.cursor], edx
    mov esi, dword [esp]
    mov eax, esi
    push ebx
    call _kmalloc
    pop ebx
    mov ecx, esi
    mov esi, eax
    mov eax, (-ENOMEM)
    jc _syscall_send_finish
    mov dword [ebx+_socket.buffer], esi
    mov dword [ebx+_socket.stand], ecx
    xchg esi, edi
_syscall_send_copy:
    mov eax, ecx
    call _copy_string
_syscall_send_finish:
    add esp, 4H
    ret

_syscall_receive:
 ; in:
 ;  ebx - socket number
 ;  ecx - userspace buffer
 ;  edx - userspace buffer size
 ; out: eax - return of byte copied
    mov edi, ecx
    mov esi, edx
    xchg ecx, edx
    xchg ebx, edx
    call _userspace_sanitize
    mov eax, (-EACCES)
    jc _syscall_receive_finish
    mov eax, edx
    mov ebx, dword [_current]
    xor edx, edx
    mov dl, _SOCKET_FILDE
    call _process_find_socket
    mov eax, (-ENOENT)
    jc _syscall_receive_finish
    movzx eax, byte [ebx+_socket.lock]
    test eax, eax
    jz _syscall_receive_finish    
    mov ecx, dword [ebx+_socket.stand]
    cmp ecx, esi
    cmova ecx, esi
    sub dword [ebx+_socket.stand], ecx
    jnz _syscall_receive_copy
    mov byte [ebx+_socket.lock], 0H
_syscall_receive_copy:
    mov esi, dword [ebx+_socket.buffer]
    add esi, dword [ebx+_socket.cursor]
    add dword [ebx+_socket.cursor], ecx
    mov eax, ecx
    call _copy_string    
_syscall_receive_finish:
    ret

_syscall_fshsck:
 ; in: ebx - socket filde number
 ; out:
 ;  eax - 0H if the syscall succeed
 ;  ebp - [_current]
 ;  esi - socket object pointer
 ;   cf - set on error
    mov eax, ebx
    mov ebp, dword [_current]
    mov ebx, ebp
    xor edx, edx
    mov dl, _SOCKET_FILDE
    call _process_find_socket
    mov eax, (-ENOENT)
    jc _syscall_fshsck_exit
    xor eax, eax
    mov byte [ebx+_socket.lock], al
    mov dword [ebx+_socket.stand], eax
    mov dword [ebx+_socket.cursor], eax
    xchg eax, dword [ebx+_socket.buffer]
    mov esi, ebx
    call _kfree
    mov eax, (-EFAULT)
    jc _syscall_fshsck_exit
    xor eax, eax
_syscall_fshsck_exit:
    ret

_syscall_unbind:
 ; in: ebx - socket filde number
 ;  eax - 0H if the syscall succeed
 ;  ebp - [_current]
 ;  esi - socket object pointer
 ;   cf - set on error
    call _syscall_fshsck
    jc _syscall_unbind_exit
    movzx eax, byte [esi+_socket.bind]
    test al, al
    jz _syscall_unbind_exit
    xor ecx, ecx
    mov byte [esi+_socket.bind], cl
    xchg cx, word [esi+_socket.port]
    lea eax, [ebp+_process.ports]
    call _convert_port_bitmap
    xor ecx, ecx
    inc cl
    mov edi, _BITMAP_RESET
    call _bitmap_inverse
    mov eax, (-EFAULT)
    jc _syscall_unbind_exit
    xor eax, eax
_syscall_unbind_exit:
    ret

_syscall_close:
 ; in: ebx - socket number
 ; out:
 ;  eax - 0H if the syscall succeed
 ;  ebp - [_current]
 ;   cf - set on error
    call _syscall_unbind
    jc _syscall_close_exit
    lea ebx, [esi+_socket.list]
    lea edx, [ebp+_process.socket]
    call _remove_list_entry
    mov eax, (-EFAULT)
    jc _syscall_close_exit
    mov edi, _socket_cache
    call _deallocate_from_cache
    mov eax, (-EFAULT)
    jc _syscall_close_exit
    xor eax, eax
_syscall_close_exit:
    ret

_syscall_clsall:
    mov ebp, dword [_current]
    xor eax, eax
_syscall_clsall_loop:
    mov ebx, dword [ebp+_process.socket]
    test ebx, ebx
    jz _syscall_clsall_exit
    mov ebx, dword [ebx-_socket.list+_socket.filde]
    call _syscall_close
    jnc _syscall_clsall_loop
_syscall_clsall_exit:
    ret

_md5_s:
    db 007H, 00CH, 011H, 016H, 007H, 00CH, 011H, 016H, 007H, 00CH, 011H, 016H, 007H, 00CH, 011H, 016H
    db 005H, 009H, 00EH, 014H, 005H, 009H, 00EH, 014H, 005H, 009H, 00EH, 014H, 005H, 009H, 00EH, 014H
    db 004H, 00BH, 010H, 017H, 004H, 00BH, 010H, 017H, 004H, 00BH, 010H, 017H, 004H, 00BH, 010H, 017H
    db 006H, 00AH, 00FH, 015H, 006H, 00AH, 00FH, 015H, 006H, 00AH, 00FH, 015H, 006H, 00AH, 00FH, 015H
_md5_s_end:

_md5_K:
    dd 0D76AA478H, 0E8C7B756H, 0242070DBH, 0C1BDCEEEH
    dd 0F57C0FAFH, 04787C62AH, 0A8304613H, 0FD469501H
    dd 0698098D8H, 08B44F7AFH, 0FFFF5BB1H, 0895CD7BEH
    dd 06B901122H, 0FD987193H, 0A679438EH, 049B40821H
    dd 0F61E2562H, 0C040B340H, 0265E5A51H, 0E9B6C7AAH
    dd 0D62F105DH, 002441453H, 0D8A1E681H, 0E7D3FBC8H
    dd 021E1CDE6H, 0C33707D6H, 0F4D50D87H, 0455A14EDH
    dd 0A9E3E905H, 0FCEFA3F8H, 0676F02D9H, 08D2A4C8AH
    dd 0FFFA3942H, 08771F681H, 06D9D6122H, 0FDE5380CH
    dd 0A4BEEA44H, 04BDECFA9H, 0F6BB4B60H, 0BEBFBC70H
    dd 0289B7EC6H, 0EAA127FAH, 0D4EF3085H, 004881D05H
    dd 0D9D4D039H, 0E6DB99E5H, 01FA27CF8H, 0C4AC5665H
    dd 0F4292244H, 0432AFF97H, 0AB9423A7H, 0FC93A039H
    dd 0655B59C3H, 08F0CCC92H, 0FFEFF47DH, 085845DD1H
    dd 06FA87E4FH, 0FE2CE6E0H, 0A3014314H, 04E0811A1H
    dd 0F7537E82H, 0BD3AF235H, 02AD7D2BBH, 0EB86D391H
_md5_K_end:

struct _md5_context _acc0*, _acc1*, _acc2*, _acc3*, _A*, _B*, _C*, _D*, _F*, _g*
    .acc0:  dd (_acc0)
    .acc1:  dd (_acc1)
    .acc2:  dd (_acc2)
    .acc3:  dd (_acc3)
    .A:     dd (_A)
    .B:     dd (_B)
    .C:     dd (_C)
    .D:     dd (_D)
    .F:     dd (_F)
    .g:     dd (_g)
ends

_MD5_DIGEST = 020H
_syscall_md5:
 ; in:
 ;  ebx - plain text
 ;  ecx - plain text size
 ;  edx - chipher buffer
 ; note: assume edx buffer is _MD5_DIGEST size
    push ebx edx
    sub esp, _md5_context.sizeof
    mov dword [esp+_md5_context.acc0], 067452301H
    mov dword [esp+_md5_context.acc1], 0EFCDAB89H
    mov dword [esp+_md5_context.acc2], 098BADCFEH
    mov dword [esp+_md5_context.acc3], 010325476H
    mov esi, ecx
    call _userspace_sanitize
    mov eax, (-EFAULT)  
    jc _syscall_md5_exit
    mov ebx, edx
    xor ecx, ecx
    mov cl, _MD5_DIGEST
    call _userspace_sanitize
    mov eax, (-EFAULT)
    jc _syscall_md5_exit
    lea ecx, [esi+1H+8H] ; size + extra '1' + 8 byte size message
    ;XXX
    shr ecx, 6H
    lea eax, [ecx+1H]
    mov ebp, eax
    shl eax, 6H ; round up to the next 64-byte size
    mov edi, eax
    call _kmalloc
    mov ebx, eax
    mov eax, (-ENOMEM)
    jc _syscall_md5_exit
    mov ecx, edi
    mov edi, ebx
    call _clear_string
    xor ecx, ecx
    mov cl, 8H
    mov eax, esi
    mul ecx
    sub edi, 8H
    stosd
    mov eax, edx
    stosd
    mov edi, ebx
    mov ecx, esi
    mov esi, dword [esp+_md5_context.sizeof+4H]
    call _copy_string
    mov al, 080H
    stosb
_syscall_md5_loop:
    lea esi, [esp+_md5_context.acc0]
    lea edi, [esp+_md5_context.A]
    xor ecx, ecx
    mov cl, 010H
    call _copy_string
    xor ecx, ecx
_syscall_md5_nested:
    cmp cl, 00FH
    jbe _syscall_md5_branch_1
    cmp cl, 01FH
    jbe _syscall_md5_branch_2
    cmp cl, 02FH
    jbe _syscall_md5_branch_3
    cmp cl, 03FH
    jbe _syscall_md5_branch_4
    mov eax, (-ERANGE)
    jmp _syscall_md5_exit
_syscall_md5_branch_1:
    mov eax, dword [esp+_md5_context.B]
    mov edx, eax
    and eax, dword [esp+_md5_context.C]
    not edx
    and edx, dword [esp+_md5_context.D]
    or eax, edx
    mov edx, ecx
    jmp _syscall_md5_update
_syscall_md5_branch_2:
    mov eax, dword [esp+_md5_context.D]
    mov edx, eax
    and eax, dword [esp+_md5_context.B]
    not edx
    and edx, dword [esp+_md5_context.C]
    or eax, edx
    imul edx, ecx, 5H
    inc edx
    jmp _syscall_md5_align
_syscall_md5_branch_3:
    mov eax, dword [esp+_md5_context.B]
    xor eax, dword [esp+_md5_context.C]
    xor eax, dword [esp+_md5_context.D]
    imul edx, ecx, 3H
    add edx, 5H
    jmp _syscall_md5_align
_syscall_md5_branch_4:
    mov eax, dword [esp+_md5_context.D]
    not eax
    or eax, dword [esp+_md5_context.B]
    xor eax, dword [esp+_md5_context.C]
    imul edx, ecx, 7H
_syscall_md5_align:
    and edx, (010H - 1H)
_syscall_md5_update:
    add eax, dword [esp+_md5_context.A]
    add eax, dword [_md5_K+ecx*4H]
    add eax, dword [ebx+edx*4H]
    mov dword [esp+_md5_context.F], eax
    mov dword [esp+_md5_context.g], edx ; for consistency
    mov edx, eax
    mov eax, dword [esp+_md5_context.D]
    mov dword [esp+_md5_context.A], eax
    mov eax, dword [esp+_md5_context.C]
    mov dword [esp+_md5_context.D], eax
    mov eax, dword [esp+_md5_context.B]
    mov dword [esp+_md5_context.C], eax
    mov esi, ecx
    movzx ecx, byte [_md5_s+ecx]
    rol edx, cl
    add eax, edx
    mov dword [esp+_md5_context.B], eax
    mov ecx, esi
    inc cl
    cmp cl, 040H
    jb _syscall_md5_nested
 define _count 0H
 irp _target*, A,B,C,D
 {
  rept 1H _index:(_count), _next:(_count + 1H)
  \{
    mov eax, dword [esp+_md5_context.\#_target]
    add dword [esp+_md5_context.acc\#_index], eax
    define _count _next
  \}
 }
    dec ebp
    jnz _syscall_md5_loop
    mov eax, ebx
    call _kfree
    mov eax, (-EFAULT)
    jc _syscall_md5_exit
 rept 4H i:0H
 {
    mov edx, dword [esp+_md5_context.acc#i]
    bswap edx
    mov edi, dword [esp+_md5_context.sizeof]
    add edi, (i shl 3H)
    call _itoa_hexadecimal
 }
    xor eax, eax
_syscall_md5_exit:
    add esp, (_md5_context.sizeof+8H)
    ret

struct _sha1_context _A*, _B*, _C*, _D*, _E*
    .A:     dd (_A)
    .B:     dd (_B)
    .C:     dd (_C)
    .D:     dd (_D)
    .E:     dd (_E)
ends

_syscall_sha1:
 ; in:
 ;  ebx - plain text
 ;  ecx - plain text size
 ;  edx - chipher buffer
    lddqu xmm0, xword [_test]
    lddqu xmm1, xword [_test+010H]
    lddqu xmm2, xword [_mask]
    lddqu xmm3, xword [_message]
    pshufb xmm3, xmm2
    paddd xmm1, xmm3
    movdqa xmm4, xmm0
    sha1rnds4 xmm0, xmm1, 0H
    lddqu xmm3, xword [_message+010H]
    pshufb xmm3, xmm2
    sha1nexte xmm4, xmm3
    sha1rnds4 xmm0, xmm4, 0H
    sha1msg1 xmm0, xmm0
    sha1msg2 xmm0, xmm0
    ret

align 010H
_test:
    dd 0x10325476, 0x98BADCFE, 0xEFCDAB89, 0x67452301
    dd 0H, 0H, 0H, 0xC3D2E1F0
db 0H
_message:
    db "HELLO", 080H
    align 8H
    dq 0H, 0H, 0H, 0H, 0H

_mask:
    dq 0x08090a0b0c0d0e0f
    dq 0x0001020304050607

_syscall_sha2:
 ; in:
 ;  ebx - plain text
 ;  ecx - plain text size
 ;  edx - chipher buffer
    ret

_syscall_des:  ; XXX

_AES_SBOX_0H_0H = 063H
_aes_sbox:
    db _AES_SBOX_0H_0H, 07CH, 077H, 07BH, 0F2H, 06BH, 06FH, 0C5H, 030H, 001H, 067H, 02BH, 0FEH, 0D7H, 0ABH, 076H
    db            0CAH, 082H, 0C9H, 07DH, 0FAH, 059H, 047H, 0F0H, 0ADH, 0D4H, 0A2H, 0AFH, 09CH, 0A4H, 072H, 0C0H
    db            0B7H, 0FDH, 093H, 026H, 036H, 03FH, 0F7H, 0CCH, 034H, 0A5H, 0E5H, 0F1H, 071H, 0D8H, 031H, 015H
    db            004H, 0C7H, 023H, 0C3H, 018H, 096H, 005H, 09AH, 007H, 012H, 080H, 0E2H, 0EBH, 027H, 0B2H, 075H
    db            009H, 083H, 02CH, 01AH, 01BH, 06EH, 05AH, 0A0H, 052H, 03BH, 0D6H, 0B3H, 029H, 0E3H, 02FH, 084H
    db            053H, 0D1H, 000H, 0EDH, 020H, 0FCH, 0B1H, 05BH, 06AH, 0CBH, 0BEH, 039H, 04AH, 04CH, 058H, 0CFH
    db            0D0H, 0EFH, 0AAH, 0FBH, 043H, 04DH, 033H, 085H, 045H, 0F9H, 002H, 07FH, 050H, 03CH, 09FH, 0A8H
    db            051H, 0A3H, 040H, 08FH, 092H, 09DH, 038H, 0F5H, 0BCH, 0B6H, 0DAH, 021H, 010H, 0FFH, 0F3H, 0D2H
    db            0CDH, 00CH, 013H, 0ECH, 05FH, 097H, 044H, 017H, 0C4H, 0A7H, 07EH, 03DH, 064H, 05DH, 019H, 073H
    db            060H, 081H, 04FH, 0DCH, 022H, 02AH, 090H, 088H, 046H, 0EEH, 0B8H, 014H, 0DEH, 05EH, 00BH, 0DBH
    db            0E0H, 032H, 03AH, 00AH, 049H, 006H, 024H, 05CH, 0C2H, 0D3H, 0ACH, 062H, 091H, 095H, 0E4H, 079H
    db            0E7H, 0C8H, 037H, 06DH, 08DH, 0D5H, 04EH, 0A9H, 06CH, 056H, 0F4H, 0EAH, 065H, 07AH, 0AEH, 008H
    db            0BAH, 078H, 025H, 02EH, 01CH, 0A6H, 0B4H, 0C6H, 0E8H, 0DDH, 074H, 01FH, 04BH, 0BDH, 08BH, 08AH
    db            070H, 03EH, 0B5H, 066H, 048H, 003H, 0F6H, 00EH, 061H, 035H, 057H, 0B9H, 086H, 0C1H, 01DH, 09EH
    db            0E1H, 0F8H, 098H, 011H, 069H, 0D9H, 08EH, 094H, 09BH, 01EH, 087H, 0E9H, 0CEH, 055H, 028H, 0DFH
    db            08CH, 0A1H, 089H, 00DH, 0BFH, 0E6H, 042H, 068H, 041H, 099H, 02DH, 00FH, 0B0H, 054H, 0BBH, 016H
_aes_sbox_end:

_aes_rcon:
    db 001H, 002H, 004H, 008H, 010H
    db 020H, 040H, 080H, 01BH, 036H
_aes_rcon_end:

_aes_SubBytes:
 ; in: eax - chipher block
 ; out: eax - updated chipher block
 ; preserves: eax, edx
    mov esi, eax
    mov edi, eax
    xor ecx, ecx
_aes_SubBytes_loop:
    mov ebx, dword [edi]
    call _aes_SubBytes_translate
    stosd
    inc cl
    cmp cl, 4H
    jb _aes_SubBytes_loop
    mov eax, esi
    ret
_aes_SubBytes_translate:
 ; in: ebx - dword to translate
 ; out: eax - translated dword
 ; preserves: ecx, edx, esi, edi
    mov ebp, edx
    mov edx, ebx
    mov eax, ((_AES_SBOX_0H_0H shl 018H) or (_AES_SBOX_0H_0H shl 010H) or (_AES_SBOX_0H_0H shl 8H) or _AES_SBOX_0H_0H)
_aes_SubBytes_translate_loop:
    test edx, edx
    jz _aes_SubBytes_translate_exit
    movzx ebx, dl
    shl eax, 8H
    mov al, byte [_aes_sbox+ebx]
    shr edx, 8H 
    jmp _aes_SubBytes_translate_loop
_aes_SubBytes_translate_exit:
    bswap eax
    mov edx, ebp
    ret

_aes_ShiftRows:
 ; in: eax - chipher block
 ; out: eax - updated chipher block
 ; preserves: eax, edx, esi, edi, ebp
    test byte [_singleton.ssse3], 1H
    jnz _aes_ShiftRows_smid
    mov ecx, edx
    mov bl, byte [eax+4H]
 rept 3H _index:5H
 {
    mov dl, byte [eax+_index]
    mov byte [eax+_index-1H], dl
 }
    mov byte [eax+7H], bl
 rept 2H _index:8H
 {
    mov dl, byte [eax+_index]
    xchg byte [eax+_index+2H], dl
    mov byte [eax+_index], dl
 }
    mov bl, byte [eax+00FH]
 irp _index*, 00EH,00DH,00CH
 {
    mov dl, byte [eax+_index]
    mov byte [eax+_index+1H], dl
 }
    mov byte [eax+00CH], bl
    mov edx, ecx
    jmp _aes_ShiftRows_exit
_aes_ShiftRows_smid:
    movdqu xmm0, xword [eax]
    pshufb xmm0, xword [_aes_ShiftRows_mask]
    movdqu xword [eax], xmm0
_aes_ShiftRows_exit:
    ret
align 010H
_aes_ShiftRows_mask:
    db 000H, 001H, 002H, 003H
    db 005H, 006H, 007H, 004H
    db 00AH, 00BH, 008H, 009H
    db 00FH, 00CH, 00DH, 00EH

_aes_MixColumns:
 ; in: eax - chipher block
 ; out: eax - updated chipher block
 ; preserves: eax, edx
    sub esp, 8H ; ([esp] - [esp+3H]) -> copy, ([esp+4H] - [esp+7H]) -> copy * 2H
    mov ebp, edx
    xor ecx, ecx
_aes_MixColumns_loop:
    lea esi, [eax+ecx]
    xor edi, edi
_aes_MixColumns_nested:
    mov dl, byte [esi+edi*4H]
    mov byte [esp+edi], dl
    mov bl, dl
    shl dl, 1H
    shr bl, 7H
    jz _aes_MixColumns_add
    mov bl, 01BH
_aes_MixColumns_add:
    xor dl, bl
    mov byte [esp+edi+4H], dl
    inc edi
    cmp edi, 4H
    jb _aes_MixColumns_nested
    mov dl, byte [esp+4H]
    xor dl, byte [esp+4H+1H]
    xor dl, byte [esp+1H]
    xor dl, byte [esp+2H]
    xor dl, byte [esp+3H]
    mov byte [esi], dl ; [2H, 3H, 1H, 1H]
    mov dl, byte [esp]
    xor dl, byte [esp+4H+1H]
    xor dl, byte [esp+4H+2H]
    xor dl, byte [esp+2H]
    xor dl, byte [esp+3H]
    mov byte [esi+4H], dl ; [1H, 2H, 3H, 1H]
    mov dl, byte [esp]
    xor dl, byte [esp+1H]
    xor dl, byte [esp+4H+2H]
    xor dl, byte [esp+4H+3H]
    xor dl, byte [esp+3H]
    mov byte [esi+8H], dl ; [1H, 1H, 2H, 3H]
    mov dl, byte [esp+4H]
    xor dl, byte [esp]
    xor dl, byte [esp+1H]
    xor dl, byte [esp+2H]
    xor dl, byte [esp+4H+3H]
    mov byte [esi+00CH], dl ; [3H, 1H, 1H, 2H]
    inc cl
    cmp cl, 4H
    jb _aes_MixColumns_loop
_aes_MixColums_exit:
    mov edx, ebp
    add esp, 8H
    ret

_aes_AddRoundKey:
 ; in:
 ;  eax - chipher block
 ;  edx - round key (aligned & unaligned 16-byte)
 ; out: eax - updated chipher block
 ; preserves: eax, ebx, edx, esi, edi, ebp
    test byte [_singleton.sse2], 1H
    jnz _aes_AddRoundKey_smid
 rept 4H i:0H
 {
    mov ecx, dword [edx+i*4H]
    xor dword [eax+i*4H], ecx
 }
    jmp _aes_AddRoundKey_exit
_aes_AddRoundKey_smid:
    movdqu xmm0, xword [eax]
    movdqu xmm1, xword [edx]
    pxor xmm0, xword xmm1
    movdqu xword [eax], xmm0
_aes_AddRoundKey_exit:
    ret

_aes_KeySchedule:
 ; in:
 ;  ecx - round number
 ;  edx - round key
 ; out: edx - updated round key
 ; preserves: eax, edx
    mov esi, eax
    movzx ecx, byte [_aes_rcon+ecx]
    mov byte [_aes_KeySchedule_smid], cl
    mov edi, ecx
    mov cl, 3H
    call _aes_KeySchedule_clextr
    test byte [_singleton.sse41], 1H
    jz _aes_KeySchedule_legacy
    test byte [_singleton.aes], 1H
    jz _aes_KeySchedule_legacy
    pinsrd xmm0, ebx, 1B
    aeskeygenassist xmm0, xmm0, 0H
    label _aes_KeySchedule_smid byte at ($ - 1H)
    pextrd eax, xmm0, 1B
    jmp _aes_KeySchedule_loop
_aes_KeySchedule_legacy:
    ror ebx, 8H
    call _aes_SubBytes_translate
    xor eax, edi
_aes_KeySchedule_loop:
 rept 4H i:0H
 {
  if ((i) <> 0H)
    mov cl, i
  else
    xor cl, cl
  end if
    call _aes_KeySchedule_clextr
    xor ebx, eax
    mov eax, ebx
    call _aes_KeySchedule_clinst
 }
    mov eax, esi
    ret
_aes_KeySchedule_clextr:
 ; in:
 ;  ecx - wanted columns
 ;  edx - round key
 ; out: ebx - columns extracted
 ; preserves: eax, ecx, edx, esi, edi, ebp
    cmp ecx, 4H
    cmc
    jc _aes_KeySchedule_clextr_exit
    test byte [_singleton.ssse3], 1H
    jz _aes_KeySchedule_clextr_legacy
    mov byte [_aes_KeySchedule_clextr_smid], cl
    movdqu xmm0, xword [edx]
    pshufb xmm0, xword [_aes_KeySchedule_mask]
    pextrd ebx, xmm0, 0H
    label _aes_KeySchedule_clextr_smid byte at ($ - 1H)
    jmp _aes_KeySchedule_clextr_exit
_aes_KeySchedule_clextr_legacy:
    movzx ebx, byte [edx+ecx]
 rept 3H i:1H
 {
    ror ebx, 8H
    or bl, byte [edx+ecx+(i*4H)]
 }
    ror ebx, 8H
_aes_KeySchedule_clextr_exit:
    ret
_aes_KeySchedule_clinst:
 ; in:
 ;  ecx - wanted columns
 ;  ebx - columns to insert
 ;  edx - round key
 ; preserves: eax, ecx, edx, esi, edi, ebp
    cmp ecx, 4H
    cmc
    jc _aes_KeySchedule_clinst_exit
    test byte [_singleton.ssse3], 1H
    jz _aes_KeySchedule_clinst_legacy
    mov byte [_aes_KeySchedule_clinst_simd], cl
    movdqu xmm0, xword [edx]
    pshufb xmm0, xword [_aes_KeySchedule_mask]
    pinsrd xmm0, ebx, 0H
    label _aes_KeySchedule_clinst_simd byte at ($ - 1H)
    pshufb xmm0, xword [_aes_KeySchedule_mask]
    movdqu xword [edx], xmm0
    jmp _aes_KeySchedule_clinst_exit
_aes_KeySchedule_clinst_legacy:
 rept 4H i:0H
 {
    mov byte [edx+ecx+(i*4H)], bl
    shr ebx, 8H
 }
_aes_KeySchedule_clinst_exit:
    ret
align 010H
_aes_KeySchedule_mask:
    db 000H, 004H, 008H, 00CH
    db 001H, 005H, 009H, 00DH
    db 002H, 006H, 00AH, 00EH
    db 003H, 007H, 00BH, 00FH

_aesenc_init_round:
 ; in:
 ;  eax - chipher block
 ;  edx - round key
 ; out:
 ;  eax - updated chipher block
 ;  edx - updated round key
 ; preserves: eax, edx
    call _aes_AddRoundKey
    xor ecx, ecx
    jmp _aes_KeySchedule

_aesenc_round:
 ; in:
 ;  eax - chipher block
 ;  ecx - round count
 ;  edx - round key
 ; out:
 ;  eax - updated chipher block
 ;  ecx - updated round count
 ;  edx - updated round key
 ; preserves: eax, edx
    push ecx
    test byte [_singleton.aes], 1H
    jnz _aesenc_round_smid
    call _aes_SubBytes
    call _aes_ShiftRows
    call _aes_MixColumns
    call _aes_AddRoundKey
    jmp _aesenc_round_exit
_aesenc_round_smid:
    movdqu xmm0, xword [eax]
    movdqu xmm1, xword [edx]
    pshufb xmm0, [_aes_KeySchedule_mask]
    pshufb xmm1, [_aes_KeySchedule_mask]
    aesenc xmm0, xmm1
    pshufb xmm0, [_aes_KeySchedule_mask]
    movdqu xword [eax], xmm0
_aesenc_round_exit:
    mov ecx, dword [esp]
    call _aes_KeySchedule
    pop ecx
    inc ecx
    ret

_aesenc_final_round:
 ; in:
 ;  eax - chipher block
 ;  edx - round key
 ; out: eax - updated chipher block
 ; preserves: eax, edx
    test byte [_singleton.aes], 1H
    jnz _aesenc_final_round_smid
    call _aes_SubBytes
    call _aes_ShiftRows
    call _aes_AddRoundKey
    jmp _aesenc_final_round_exit
_aesenc_final_round_smid:
    movdqu xmm0, xword [eax]
    movdqu xmm1, xword [edx]
    pshufb xmm0, [_aes_KeySchedule_mask]
    pshufb xmm1, [_aes_KeySchedule_mask]
    aesenclast xmm0, xmm1
    pshufb xmm0, [_aes_KeySchedule_mask]
    movdqu xword [eax], xmm0
_aesenc_final_round_exit:
    ret

_syscall_aesenc_ecb:
 ; in:
 ;  ebx - plain text
 ;  ecx - plain text size
 ;  edx - key (assume 16-byte)
 ;  esi - output buffer
 ;  edi - output size
    sub esp, (020H + 8H)
    test ecx, ecx
    jz _syscall_aesenc_ecb_exit-2H
    mov esi, ebx
    mov edi, ecx
    mov ebp, edx
    call _userspace_sanitize
    mov eax, (-EFAULT)
    jc _syscall_aesenc_ecb_exit
    mov ebx, edx
    xor ecx, ecx
    mov cl, 010H
    call _userspace_sanitize
    mov eax, (-EFAULT)
    jc _syscall_aesenc_ecb_exit
    mov eax, esi
    mov ebx, edi
    mov esi, ebp
    mov edi, esp
    xor ecx, ecx
    mov cl, 010H
    call _copy_string_user
    mov esi, ebp
    mov cl, 010H
    call _copy_string
    mov esi, eax
    mov edi, ebx
    mov eax, edi
    shrd ecx, eax, 4H
    shr eax, 4H
    jecxz $+3H
    inc eax
    mov dword [esp+020H], eax
    shl eax, 4H 
    mov ebp, eax
    call _kmalloc
    mov dword [esp+024H], eax
    mov eax, (-ENOMEM)
    jc _syscall_aesenc_ecb_exit
    mov ecx, ebx
    xchg edi, ecx
    sub ebp, ecx
    call _copy_string_user
    mov ecx, ebp
    call _clear_string
    mov eax, dword [esp+024H]
_syscall_aesenc_ecb_loop:
    lea edi, [esp+010H]
    mov edi, esp
    xor ecx, ecx
    mov cl, 010H
    call _copy_string
    lea edx, [esp+010H]
    call _aesenc_init_round
    xor ecx, ecx
    inc cl
 rept 9H { call _aesenc_round }
    call _aesenc_final_round
    add eax, 010H
    dec dword [esp+020H]
    jnz _syscall_aesenc_ecb_loop
    mov eax, dword [esp+024H]
    call _kfree
    xor eax, eax
_syscall_aesenc_ecb_exit:
    add esp, (020H + 8H)
    ret

_syscall_aesenc_cbc:
    ret

_syscall_aesdec:
    ret

_syscall_read:
 ; in:
 ;  ebx - tty number
 ;  ecx - target buffer
 ;  edx - target buffer size
    call _retreive_teletype
    mov eax, (-EINVAL)
    jc _syscall_read_exit
    push ecx edx
    xor eax, eax
    mov al, _SEND_SIGTTIN
    call _process_foreground_group_current
    mov eax, (-ENOTTY)
    pop edx ecx
    jc _syscall_read_exit
    mov esi, ebx
    mov edi, ecx
    mov ebp, edx
    xchg ecx, edx
    xchg ebx, edx
    call _userspace_sanitize
    mov eax, (-EFAULT)
    jc _syscall_read_exit
    mov ebx, edx
_syscall_read_loop:
    movzx ecx, word [ebx+_teletype.index]
    test byte [ebx+_teletype.termios.lflag], ICANON
    jnz _syscall_read_cookie
    jecxz _syscall_read_sleep
    movzx eax, word [ebx+_teletype.termios.vmin]
    cmp cx, ax
    jae _syscall_read_transfer
_syscall_read_sleep:
    mov eax, dword [_current]
    xchg eax, ebx
    call _sleep_channel ; sleep on teletype object pointer
    mov ebx, esi
    jmp _syscall_read_loop
_syscall_read_cookie:
    cmp byte [ebx+_teletype.eoi], 0H
    jz _syscall_read_sleep
    movzx ecx, word [ebx+_teletype.ceidx]
    cmp ecx, ebp
    ja _syscall_read_transfer
    mov byte [ebx+_teletype.eoi], 0H
_syscall_read_transfer:
    call _switch_mapping_user ; XXX switching needed?
    cmp ecx, ebp
    cmova ecx, ebp
    mov ebp, ecx
    jecxz _syscall_read_exit-2H
    mov esi, dword [ebx+_teletype.input]
    mov eax, esi
    call _copy_string
    mov edi, eax
    lea ecx, [ebp-_TELETYPE_INPUT]
    neg ecx
    call _copy_string
    sub word [ebx+_teletype.index], bp
    test byte [ebx+_teletype.termios.lflag], ICANON
    jz _syscall_read_exit-2H
    sub word [ebx+_teletype.ceidx], bp
    mov eax, ebp
_syscall_read_exit:
    ret

WCOREFLAG = 200H
_syscall_exit:
 ; in: ebx - exit code status
    call _switch_mapping_kernel
    call _syscall_clsall ; close all opened socket with the current process
    jc _panic
    mov esi, dword [_current]
    mov dword [esi+_process.extcde], ebx
    mov dword [esi+_process.state], _PROCESS_ZOMBIE
    mov ebx, esi
    mov esi, dword [esi+_process.mapping]
    call _reset_mapping
    mov esi, ebx
    ;XXX
    ;mov ebx, esi
    ;call _syscall_daemon_dettach
    mov ebp, dword [_initproc]
    mov edi, ebp
    cmp esi, edi
    jnz _syscall_exit_scheduler
    cmp byte [esi+_process.panic], 0H
    jz _power_off
    jmp _panic
_syscall_exit_scheduler:
    cmp esi, dword [_scheduler]
    jz _panic
    mov ebx, esi
    mov esi, _syscall_exit_reparent
    call _process_iterate_childs
    mov esi, ebx
_syscall_exit_migrate:
    lea eax, dword [esi+_process.childs]
    lea edx, dword [edi+_process.childs]
    call _assign_list
    jnc _syscall_exit_migrate
    mov ebx, dword [esi+_process.parent]
    mov esi, _syscall_exit_allzmbs
    call _process_iterate_childs
    mov esi, ebx
    jnc _syscall_exit_wakefath
    mov byte [esi+_process.allzmbs], _PROCESS_ZOMBIES
_syscall_exit_wakefath:
    cmp esi, edi
    jz _syscall_exit_wakeinit
    mov eax, dword [esi+_process.channel]
    call _wakeup_channel 
_syscall_exit_wakeinit:
    mov eax, dword [edi+_process.channel]
    call _wakeup_channel 
    jmp _reschedule
_syscall_exit_allzmbs:
    cmp dword [ebx+_process.state], _PROCESS_ZOMBIE
    jmp _invert_zero_carry
_syscall_exit_reparent:
    mov dword [ebx+_process.parent], ebp
    ret

; WIFEXITED(x)      -> (((x) and 07FH) = 0H)
; WIFSIGNALED(x)    -> (((((x) and 07FH) + 1H) shr 1H) > 0H)
; WIFSTOPPED(x)     -> (((x) and 0FFH) = 07FH)
; WIFCONTINUED(x)   -> ((x) = 0FFFFH)
enum & WNOHANG, WSTOPPED, WEXITED, WCONTINUED, WNOWAIT
_WAIT_ALL = (not 0H)
_WSTOPPED = 07FH
_WCONTINUED = 0FFFFH
_syscall_waitpid:
 ; in:
 ;  ebx - pid to search (-1H to check all child)
 ;  ecx - exit status (ignored if ecx = 0H)
 ;  edx - options
 ; note: don't support group pid for now
    push ebx ecx edx
    push 0H ; exit status
    cmp ebx, _WAIT_ALL
    mov eax, (-EINVAL)
    jl _syscall_waitpid_exit
    test edx, (not (WNOHANG or WSTOPPED or WEXITED or WCONTINUED or WNOWAIT))
    jnz _syscall_waitpid_exit
    and dl, (WSTOPPED or WEXITED or WCONTINUED)
    jz _syscall_waitpid_exit
    mov edi, dword [_current]
    cmp dword [edi+_process.childs], 0H
    mov eax, (-ECHILD)
    jz _syscall_waitpid_exit
    shr dl, (WSTOPPED - 1H)
    mov esi, dword [_syscall_waitpid_switch+edx*4H]
    cmp ebx, _WAIT_ALL
    mov ebp, _syscall_waitpid_target
    jnz _syscall_waitpid_target
    mov ebp, _syscall_waitpid_all
_syscall_waitpid_all:
    test byte [esp+4H], WEXITED
    jnz _syscall_waitpid_all_find
    cmp byte [edi+_process.allzmbs], _PROCESS_ZOMBIES
    mov eax, (-ECHILD)
    jz _syscall_waitpid_exit
_syscall_waitpid_all_find:
    mov ebx, edi
    call _process_iterate_childs
    mov ebx, eax
    cmc
    jmp _syscall_waitpid_continue
_syscall_waitpid_target:
    xor edx, edx
    test byte [esp+4H], WEXITED
    jz _syscall_waitpid_target_search
    or dl, _SEARCH_ZOMBIE_CHILD
_syscall_waitpid_target_search:
    or dl, _SEARCH_ALIVE_CHILD
    mov eax, dword [esp+00CH]
    call _search_pid
    mov eax, (-ECHILD)
    jc _syscall_waitpid_exit
    lea esp, [esp-(_ITERATE_CHILD_REMAINS-4H)] ; mimic the stack layout from _find_list
    call esi
    lea esp, [esp+(_ITERATE_CHILD_REMAINS-4H)]
_syscall_waitpid_continue:
    jc _syscall_waitpid_notify
    xor eax, eax
    test byte [esp+4H], WNOHANG
    jnz _syscall_waitpid_exit
    mov ebx, edi
    mov eax, edi ; use pointer [_current] for the channel id
    call _sleep_channel
    jmp ebp
_syscall_waitpid_notify:
    call _switch_mapping_user
    ; XXX need the switching needed?
    mov esi, ebx
    mov ebx, dword [esp+8H]
    test ebx, ebx
    jz _syscall_waitpid_free
    mov edi, ebx
    xor ecx, ecx
    mov cl, 4H
    call _userspace_sanitize
    mov eax, (-EFAULT)
    jc _syscall_waitpid_exit
    mov eax, dword [esp]
    mov dword [edi], eax
_syscall_waitpid_free:
    push dword [esi+_process.pid]
    test byte [esp+8H], WEXITED
    jz _syscall_waitpid_retreive
    cmp byte [esp+4H], _WSTOPPED
    jz _syscall_waitpid_retreive
    cmp word [esp+4H], _WCONTINUED
    jz _syscall_waitpid_retreive
    mov ebx, esi
    call _destroy_process
_syscall_waitpid_retreive:
    pop eax
_syscall_waitpid_exit:
    lea esp, [esp+010H]
    ret
_syscall_waitpid_switch:
    dd 0H
    dd _syscall_waitpid_stopped
    dd _syscall_waitpid_zombie
    dd _syscall_waitpid_stopped_zombie
    dd _syscall_waitpid_continued
    dd _syscall_waitpid_stopped_continued
    dd _syscall_waitpid_zombie_continued
    dd _syscall_waitpid_stopped_zombie_continued
_syscall_waitpid_stopped:
    cmp dword [ebx+_process.state], _PROCESS_STOP
    jnz _syscall_waitpid_stopped_exit
    cmp byte [ebx+_process.waitable], _PROCESS_WAITABLE
    jnz _syscall_waitpid_stopped_exit
    movzx eax, byte [ebx+_process.sigstp]
    shl eax, 8H
    mov al, _WSTOPPED
    mov dword [esp+_ITERATE_CHILD_REMAINS], eax
    test byte [esp+_ITERATE_CHILD_REMAINS+4H], WNOWAIT
    jnz _invert_zero_carry
    mov byte [ebx+_process.waitable], 0H
_syscall_waitpid_stopped_exit:
    jmp _convert_zero_carry
_syscall_waitpid_zombie:
    cmp dword [ebx+_process.state], _PROCESS_ZOMBIE
    jnz _syscall_waitpid_zombie_exit
    movzx eax, byte [ebx+_process.extcde]
    shl eax, 8H
    mov al, byte [ebx+_process.extsig]
    mov dword [esp+_ITERATE_CHILD_REMAINS], eax
    xor al, al ; set ZF
_syscall_waitpid_zombie_exit:
    jmp _convert_zero_carry
_syscall_waitpid_stopped_zombie:
    pop ebp
    push _syscall_waitpid_stopped_zombie_next
    jmp _syscall_waitpid_stopped
_syscall_waitpid_stopped_zombie_next:
    jc _syscall_waitpid_stopped_zombie_exit
    push _syscall_waitpid_stopped_zombie_exit
    jmp _syscall_waitpid_zombie
_syscall_waitpid_stopped_zombie_exit:
    jmp ebp
_syscall_waitpid_continued:
    cmp dword [ebx+_process.state], _PROCESS_RUN
    jnz _syscall_waitpid_continued_exit
    cmp byte [ebx+_process.waitable], _PROCESS_WAITABLE
    jnz _syscall_waitpid_continued_exit
    mov dword [esp+_ITERATE_CHILD_REMAINS], _WCONTINUED
    test byte [esp+_ITERATE_CHILD_REMAINS+4H], WNOWAIT
    jnz _invert_zero_carry
    mov byte [ebx+_process.waitable], 0H
_syscall_waitpid_continued_exit:
    jmp _convert_zero_carry
_syscall_waitpid_stopped_continued:
    pop ebp
    push _syscall_waitpid_stopped_continued_next
    jmp _syscall_waitpid_stopped
_syscall_waitpid_stopped_continued_next:
    jc _syscall_waitpid_stopped_continued_exit
    push _syscall_waitpid_stopped_continued_exit
    jmp _syscall_waitpid_continued
_syscall_waitpid_stopped_continued_exit:
    jmp ebp
_syscall_waitpid_zombie_continued:
    pop ebp
    push _syscall_waitpid_zombie_continued_next
    jmp _syscall_waitpid_zombie
_syscall_waitpid_zombie_continued_next:
    jc _syscall_waitpid_zombie_continued_exit
    push _syscall_waitpid_zombie_continued_exit
    jmp _syscall_waitpid_continued
_syscall_waitpid_zombie_continued_exit:
    jmp ebp
_syscall_waitpid_stopped_zombie_continued:
    pop ebp
    push _syscall_waitpid_stopped_zombie_continued_next_1
    jmp _syscall_waitpid_stopped
_syscall_waitpid_stopped_zombie_continued_next_1:
    jc _syscall_waitpid_stopped_zombie_continued_exit
    push _syscall_waitpid_stopped_zombie_continued_next_2
    jmp _syscall_waitpid_zombie
_syscall_waitpid_stopped_zombie_continued_next_2:
    jc _syscall_waitpid_stopped_zombie_continued_exit
    jmp _syscall_waitpid_continued
_syscall_waitpid_stopped_zombie_continued_exit:
    jmp ebp

_syscall_wait:
 ; in: ebx - exit status
 ; out: eax - same as _syscall_waitpid
    mov ecx, ebx
    xor edx, edx
    mov dl, WEXITED
    mov bl, _WAIT_ALL
    movsx ebx, bl
    jmp _syscall_waitpid

_syscall_align:
 ; note: it's kind of a debug syscall. Once set the current program can't revert back.
    mov ebx, dword [_current]
    mov eax, (not EFAULT)
    cmp dword [ebx+_process.pid], _INIT_PID
    jz _syscall_align_exit+2H
    cmp byte [ebx+_process.align], 0H
    jnz _syscall_align_exit
    not byte [ebx+_process.align]
    call _set_cr0_am
_syscall_align_exit:
    xor eax, eax
    ret

_syscall_test:
    ;movzx eax, byte [_tty1.fground]
    ;mov eax, dword [_tty1.grpdesc]
    ;mov eax, dword [eax+_process_group_descriptor.pgid]
_def:
    jmp _USER_CODE_VIRTUAL
    ;mov eax, 0DEADH
    ;mov ebx, dword [_current]
    ;call _sleep_channel
    ret

_syscall_daemon:
 ; in: ebx - target uid
 ; preserves: esi, edi, ebp
 ; note: don't be a problem when executed several time on the same process
    mov eax, ebx
    mov edx, _SEARCH_ALIVE_SYSTEM
    call _search_pid
    mov eax, (-ESRCH)
    jc _syscall_daemon_exit
    call _uid_enough_permission
    jc _syscall_daemon_dettach
    mov eax, (-EPERM)
    jmp _syscall_daemon_exit
_syscall_daemon_dettach:
    cmp byte [ebx+_process.daemon], 0H
    jnz _syscall_daemon_exit-2H
    mov byte [ebx+_process.daemon], (not 0H)
    mov eax, dword [ebx+_process.tty]
    ;lea ebx, [ebx+_process.fground]
    ;lea edx, [eax+_teletype.attach]
    ;call _remove_list_entry
    xor eax, eax
_syscall_daemon_exit:
    ret

_syscall_renice:
 ; in:
 ;  ebx - target uid
 ;  ecx - new priority level
    mov eax, (-EINVAL)
    cmp ecx, _PROCESS_NICE
    jae _syscall_renice_exit
    mov esi, ecx
    mov eax, ebx
    mov edx, _SEARCH_ALIVE_SYSTEM
    call _search_pid
    mov eax, (-ESRCH)
    jc _syscall_kill_exit
    call _uid_enough_permission
    jc _syscall_renice_perform
    mov eax, (-EPERM)
    jmp _syscall_renice_exit
_syscall_renice_perform:
    mov dword [ebx+_process.increment], esi
    xor eax, eax
_syscall_renice_exit:
    ret

_syscall_guid:
 ; preserves: ebx, ecx, edx, esi, edi, ebp
    mov eax, dword [_current]
    mov eax, dword [eax+_process.uid]
    ret

_syscall_suid:
 ; in: ebx - target uid
    mov edx, dword [_current]
    mov eax, (-EPERM)
    cmp dword [edx+_process.uid], _ROOT_UID
    jnz _syscall_suid_exit
    mov dword [edx+_process.uid], ebx
    xor eax, eax
_syscall_suid_exit:
    ret

_syscall_gpid:
 ; out: eax - current process id
 ; preserves: ebx, ecx, edx, esi, edi, ebp
    mov eax, dword [_current]
    mov eax, dword [eax+_process.pid]
    ret

_syscall_gtid:
    mov eax, dword [_current]
    mov eax, dword [eax+_process.tid]
    ret

_syscall_gppid:
    mov ebx, dword [_current]
    cmp ebx, _scheduler
    mov eax, (-EFAULT)
    jz _syscall_gppid_exit
    mov ebx, dword [ebx+_process.parent]
    mov eax, dword [ebx+_process.pid]
_syscall_gppid_exit:
    ret

_syscall_gsid:
 ; in: ebx - target uid
    mov dl, _SEARCH_ALIVE_SYSTEM
    call _find_task
    jc _syscall_gsid_exit
    mov eax, dword [_current]
    mov eax, dword [eax+_process.sid]
    mov ebx, dword [ebx+_process.sid]
    cmp eax, ebx
    mov eax, (-EPERM)
    jnz _syscall_gsid_exit
    mov eax, ebx
_syscall_gsid_exit:
    ret

_syscall_ssid:
 ; out:
 ;  eax - new session id
 ;   cf - set on error
    mov esi, dword [_current]
    cmp byte [esi+_process.grplead], 0H
    mov eax, (-EPERM)
    stc
    jnz _syscall_ssid_exit
    xor eax, eax
    mov al, _ALLOCATION_VIRTUAL
    mov edi, _session_cache
    call _allocate_from_cache
    mov eax, (-ENOMEM)
    jc _syscall_ssid_exit
    mov eax, dword [esi+_process.pid]
    mov dword [esi+_process.sid], eax
    mov dword [ebx+_session_descriptor.sid], eax
    mov dword [esi+_process.sesdesc], ebx
    mov dword [ebx+_session_descriptor.leader], esi
    mov ecx, _session_descriptor.list
    call _doubly_linked
    push ebx
    mov edx, _session_list
    call _assign_list_esp
    call _syscall_spgrp
    jc _syscall_ssid_exit
    mov byte [ebp+_process.seslead], (not 0H)
    mov eax, dword [ebp+_process.sid]
_syscall_ssid_exit:
    ret

_find_task:
 ; in:
 ;  ebx - target uid
 ;   dl - kind to search
 ; out:
 ;  ebx - process object pointer
 ;   cf - set if not found
 ; preserves: esi, edi, ebp
 ; note: if uid is 0H return the current process, otherwise search in the whole system or just the children
    cmp ebx, 0H
    mov eax, (-EINVAL)
    stc
    jl _find_task_exit
_find_task_zero:
    test ebx, ebx
    jnz _find_task_search
_find_task_current:
    mov ebx, dword [_current]
    jmp _find_task_exit
_find_task_search:
    cmp dl, _SEARCH_ALIVE_CHILD
    jnz _find_task_perform
    call _syscall_gpid
    cmp eax, ebx
    jz _find_task_current
_find_task_perform:
    movzx edx, dl
    mov eax, ebx
    call _search_pid
    mov eax, (-EPERM)
_find_task_exit:
    ret

_syscall_gpgrp:
 ; note: version POSIX.1
    xor ebx, ebx
_syscall_gpgid:
 ; in: ebx - target uid
    mov dl, _SEARCH_ALIVE_SYSTEM
    call _find_task
    jc _syscall_gpgid_exit
    mov eax, dword [ebx+_process.pgid]
_syscall_gpgid_exit:
    ret

_syscall_spgrp:
 ; note: version Sytem V
    xor ebx, ebx
    xor ecx, ecx
_syscall_spgid:
 ; in:
 ;  ebx - target pid
 ;  ecx - target pgid
 ; out:
 ;  ebp - changed process object pointer ([_current] if ebx = 0H)
 ;   cf - set on error
 ; preserves: esi, edi
    mov edi, ecx
    mov dl, _SEARCH_ALIVE_CHILD
    call _find_task
    jc _syscall_spgid_exit
    test edi, edi
    jnz _syscall_spgid_search
    mov edi, dword [ebx+_process.pid]
_syscall_spgid_search:
    mov eax, dword [_current]
    mov eax, dword [eax+_process.sid]
    cmp eax, dword [ebx+_process.sid]
    mov eax, (-EPERM)
    jnz _syscall_spgid_exit
    cmp byte [ebx+_process.seslead], 0H
    jnz _syscall_spgid_exit
    mov ebp, ebx
    mov eax, _process_group
    mov ecx, _process_group_descriptor.list  
    xor edx, edx
    mov dl, (_LIST_FORWARD or _LIST_SAVE_ALL)
    mov esi, _syscall_spgid_match
    call _find_list
    mov esi, ebx
    jnc _syscall_spgid_found
    cmp edi, dword [ebp+_process.pid]
    mov eax, (-EPERM)
    jnz _syscall_spgid_exit
    mov esi, edi
    mov eax, _ALLOCATION_VIRTUAL
    mov edi, _process_group_cache
    call _allocate_from_cache
    mov eax, (-ENOMEM)
    jc _syscall_spgid_exit
    mov byte [ebp+_process.grplead], (not 0H)
    mov eax, dword [ebp+_process.sid]
    mov dword [ebx+_process_group_descriptor.sid], eax
    mov dword [ebx+_process_group_descriptor.pgid], esi
    mov byte [ebx+_process_group_descriptor.orphaned], 0H
    mov esi, ebx
    mov ecx, _process_group_descriptor.sess
    call _doubly_linked
    push ebx
    mov edx, dword [ebp+_process.sesdesc]
    lea edx, [edx+_session_descriptor.grplist]
    call _assign_list_esp
    mov ebx, esi
    mov ecx, _process_group_descriptor.list
    call _doubly_linked
    push ebx
    mov edx, _process_group
    call _assign_list_esp
    jmp _syscall_spgid_migrate
_syscall_spgid_found:
    xor eax, eax
    cmp edi, dword [ebp+_process.pgid] ; already in the group ?
    jz _syscall_spgid_exit
_syscall_spgid_migrate:
    mov edi, dword [ebp+_process.grpdesc]
    test edi, edi ; special case for newly created process
    jz _syscall_spgid_insert
    lea ebx, [ebp+_process.pgroup]
    lea edx, [edi+_process_group_descriptor.prclist]
    call _remove_list_entry
    jnz _syscall_spgid_insert
    lea ebx, [edi+_process_group_descriptor.sess]
    mov edx, dword [ebp+_process.sesdesc]
    add edx, _session_descriptor.grplist
    call _remove_list_entry
    lea ebx, [edi+_process_group_descriptor.list]
    mov edx, _process_group
    call _remove_list_entry
    push esi
    mov esi, edi
    mov edi, _process_group_cache
    call _deallocate_from_cache
    pop esi
    mov eax, (-ENOMEM)
    jc _syscall_spgid_exit
_syscall_spgid_insert:
    mov dword [ebp+_process.grpdesc], esi
    lea eax, [ebp+_process.pgroup]
    lea edx, [esi+_process_group_descriptor.prclist]
    call _assign_list
    lea esi, [esi+_process_group_descriptor.pgid]
    lea edi, [ebp+_process.pgid]
    movsd
    mov eax, dword [ebp+_process.pgid]
_syscall_spgid_exit:
    test eax, eax
    jns $+3H
    stc
    ret
_syscall_spgid_match:
    cmp dword [ebx+_process_group_descriptor.pgid], ecx
    jnz _convert_zero_carry
    mov eax, dword [ebp+_process.sid]
    cmp dword [ebx+_process_group_descriptor.sid], eax
    jmp _convert_zero_carry

_sanitize_signal:
 ; in: ebx - signal
 ; out: cf - invalid signal
    cmp ebx, SIGKILL
    jz _convert_zero_carry
    cmp ebx, SIGSTOP
    jz _convert_zero_carry
_sanitize_signal_bound:
    test ebx, ebx
    jz _convert_zero_carry
    cmp ebx, _SIGNALS
    cmc
    ret
 
_convert_signal_bitmask:
 ; in:
 ;  eax - bitmask pointer
 ;  ebx - signal
 ; out:
 ;  ebx - bitmask index
 ;  edx - low order bit index into the _BITMAP_UNIT
 ; preserves: eax, ecx, esi, edi, ebp
    dec ebx
    mov edx, ((_BITMAP_UNIT shl 3H) - 1H)
    and edx, ebx
    shr ebx, 3H
    and bl, (not (_BITMAP_UNIT - 1H))
    add ebx, dword [eax+_bitmap.next]
    ret
 
_convert_bitmask_signal:
 ; in:
 ;  eax - bitmask pointer
 ;  ebx - bitmask index
 ;  edx - low order bitmask index
 ; out: ebx - signal
 ; preserves: eax, ecx, edx, esi, edi, ebp
    sub ebx, dword [eax+_bitmap.next]
    shl ebx, 3H
    lea ebx, [ebx+edx+1H]
    ret
  
enum SIGBLOCK, SIGUNBLOCK
_syscall_sigmask:
 ; in:
 ;  ebx - signal kind
 ;  ecx - signal action kind
 ; out: eax = 0H if success or errno
    call _sanitize_signal
    mov eax, (-EINVAL)
    jc _syscall_sigmask_exit
    cmp ecx, SIGUNBLOCK
    ja _syscall_sigmask_exit
    mov esi, dword [_current]
    mov eax, _BITMAP_RESET
    mov edi, _BITMAP_SET
    cmp ecx, SIGUNBLOCK
    cmovz edi, eax
    lea eax, [esi+_process.sigmask]
    call _convert_signal_bitmask
    xor ecx, ecx
    inc cl
    call _bitmap_update
    xor eax, eax
_syscall_sigmask_exit:
    ret

_syscall_signal:
 ; in:
 ;  ebx - signal kind
 ;  ecx - signal handler
 ; out: eax = 0H if success or errno
    call _sanitize_signal
    mov eax, (-EINVAL)
    jc _syscall_signal_exit
    xchg ebx, ecx
    call _memory_accessible
    mov eax, (-EACCES)
    jc _syscall_signal_exit
    mov esi, dword [_current]
    shl ecx, (bsf _signal_context.sizeof)
    mov dword [esi+_process.signals+ecx+_signal_context.handler], ebx
    mov byte [esi+_process.signals+ecx+_signal_context.assign], (not 0H)
    xor eax, eax
_syscall_signal_exit:
    ret

_syscall_sigret:
    mov eax, (-EFAULT)
    mov ebx, dword [_current]
    movzx edx, byte [ebx+_process.signst]
    test edx, edx
    jz _syscall_sigret_exit
    dec byte [ebx+_process.signst]
    lea ebp, [ebx+_process.signals+_signal_context.sizeof]
    mov ecx, _SIGNALS
_syscall_sigret_loop:
    cmp byte [ebp+_signal_context.newfrm], 0H
    jz _syscall_sigret_update
    cmp byte [ebp+_signal_context.nested], dl
    jz _syscall_sigret_found
_syscall_sigret_update:
    add ebp, _signal_context.sizeof
    loop _syscall_sigret_loop
    jmp _syscall_sigret_exit
_syscall_sigret_found:
    mov byte [ebp+_signal_context.nested], 0H
    mov ebp, dword [ebp+_signal_context.sigframe]
    mov esi, ebp
    mov edi, dword [ebx+_process.retframe]
    xor ecx, ecx
    mov cl, _x86_register.sizeof
    call _copy_string
    mov edi, ebp
    xor ecx, ecx
    mov cl, _x86_register.sizeof
    call _clear_string
_syscall_sigret_exit:
    ret

_syscall_kill:
 ; in:
 ;  ebx - target pid (negative value mean to send the signal to all menber of a process group)
 ;  ecx - signal to send
    xor ebp, ebp
    mov edi, _syscall_kill_table
    test ebx, ebx
    jns _syscall_kill_sanitize
    add esi, 8H
    neg ebx
    not ebp
_syscall_kill_sanitize:
    xchg ebx, ecx
    call _sanitize_signal_bound
    mov eax, (-EINVAL)
    jc _syscall_kill_exit
    mov esi, ebx
    mov eax, ecx
    xor edx, edx
    mov dl, _SEARCH_ALIVE_SYSTEM
    call dword [edi]
    mov eax, (-ESRCH)
    jc _syscall_kill_exit
    test ebp, ebp
    jnz _syscall_kill_send
    call _uid_enough_permission
    mov eax, (-EPERM)
    jc _syscall_kill_send
    jo _syscall_kill_send
    jmp _syscall_kill_exit
_syscall_kill_send:
    mov eax, esi
    call dword [edi+4H]
    mov eax, (-EINVAL)
    jc _syscall_kill_exit
    xor eax, eax
_syscall_kill_exit:
    ret
_syscall_kill_table:
    dd _search_pid
    dd _send_signal
    dd _search_group
    dd _send_signal_process_group
_syscall_kill_table_end:

_uid_enough_permission:
 ; in: ebx - target process object pointer
 ; out:
 ;  cf - set if the current uid has enough permission to change the target process
 ;  of - when cf = 0H, set when uid does not match but are in the same session
 ; preserves: ebx, ecx, edx, esi, edi, ebp
 ; note:
 ;  if current is a root process or both the sender or receiver have the same uid
 ;  process with different uid can send SIGCONT only if they are in the same session
    call _syscall_guid
    cmp eax, _ROOT_UID
    jz _convert_zero_carry
    cmp eax, dword [ebx+_process.uid]
    jz _convert_zero_carry
    cmp dword [ebx+_process.uid], _ROOT_UID
    jz _invert_zero_carry
    call _syscall_gsid
    cmp dword [ebx+_process.sid], eax
    setz al
    ror al, 1H
    ret

_syscall_brk:
 ; in: ebx - target address
 ; out: eax - new address
 ; note:
 ;  this program break implement the lazy allocation system
 ;  if the user page fault between mnbrk and break, allocation is done automatically
    and ebx, (not _PAGE_OFFSET_MASK)
    call _memory_accessible_userspace
    mov eax, (-EINVAL)
    jc _syscall_brk_exit
    mov ebp, dword [_current]
    mov esi, dword [ebp+_process.break]
    mov edi, ebx
    cmp ebx, dword [ebp+_process.mnbrk]
    jb _syscall_brk_exit
    cmp ebx, dword [ebp+_process.ustck]
    jae _syscall_brk_exit
    sub ebx, dword [ebp+_process.break]
    mov ecx, ebx
    jz _syscall_brk_exit-2H
    ja _syscall_brk_expand
    neg ecx
    shr ecx, _PAGE_TABLE_SHIFT
    xor eax, eax
    mov al, _DEALLOCATION_VIRTUAL
    mov ebx, edi
    call _unmap_virtual_address
    jmp _syscall_brk_update
_syscall_brk_expand:
    shr ecx, _PAGE_TABLE_SHIFT
    xor al, al
    call _available_linear_range
    mov eax, (-ENOMEM)
    jc _syscall_brk_exit
_syscall_brk_update:
    mov dword [ebp+_process.break], edi
    mov eax, edi
_syscall_brk_exit:
    ret

enum _PROT_READ, _PROT_WRITE, _PROT_EXEC
_syscall_mprot:
 ; in:
 ;  ebx - target address
 ;  ecx - address length
 ;  edx - new prototype
 ; note: trying to change the attribute of a non present page is a no-op
    push edx    ; target prototype
    mov eax, (-EINVAL)
    jecxz _syscall_mprot_exit-2H
    cmp edx, (_PROT_READ or _PROT_WRITE or _PROT_EXEC)
    ja _syscall_mprot_exit
    and ebx, (not _PAGE_OFFSET_MASK)
    _align_up ecx, _PAGE_FRAME_SIZE
    mov esi, ebx
    lea edi, [esi+ecx]
    cmp edi, esi
    jb _syscall_mprot_exit
    cmp edi, _KERNEL_VIRTUAL
    mov eax, (-EACCES)
    ja _syscall_mprot_exit
    mov eax, _syscall_mprot_pte
    mov edx, _ITERATE_PTE
    call _iterate_range_linear
    mov eax, (-ENOMEM)
    jc _syscall_mprot_exit
    mov eax, _syscall_mprot_pde
    mov edx, _ITERATE_PDE
    call _iterate_range_linear
    mov eax, (-ENOMEM)
    jc _syscall_mprot_exit
    xor eax, eax
_syscall_mprot_exit:
    pop edx
    ret
irp _kind*, pde,pte
{
_syscall_mprot_#_kind:
    call _page_present
    cmc
    jnc _syscall_mprot_#_kind#_exit
    match =pde, _kind \{ jnz _syscall_mprot_#_kind#_exit \}
    match =pte, _kind \{ jz  _syscall_mprot_#_kind#_exit \}
    mov al, byte [esp+_ITERATE_REMAIN]
    call _syscall_mprot_flags
_syscall_mprot_#_kind#_exit:
    ret
}
_syscall_mprot_flags:
 ; note: assume flags in al are correct
    test al, _PROT_WRITE
    jz _syscall_mprot_flags_write
    or byte [ebx], _PE_READ_WRITE
    and dword [ebx], (not _PE_RDO)
    jmp _syscall_mprot_flags_next
_syscall_mprot_flags_write:
    and byte [ebx], (not _PE_READ_WRITE)
    test dword [ebx], _PE_COW
    jnz _syscall_mprot_flags_next
    or dword [ebx], _PE_RDO
_syscall_mprot_flags_next:
    test byte [_singleton.pae], 1H
    jz _syscall_mprot_flags_exit
    test al, _PROT_EXEC
    jz _syscall_mprot_flags_exec
    and dword [ebx+4H], (not (_PAE_XD shr 020H))
    jmp _syscall_mprot_flags_exit
_syscall_mprot_flags_exec:
    or dword [ebx+4H], (_PAE_XD shr 020H)
_syscall_mprot_flags_exit:
    call _linear_make_no_recursive
    invlpg [ebx]
    ret

enum & _AMAP_BIG, _AMAP_FIXED
_syscall_amap:
 ; in:
 ;  ebx - hint address
 ;  ecx - address length to allocate
 ;  edx - prototype
 ;  esi - flags
 ; out: eax = target address if success or errno
    mov eax, (-EINVAL)
    cmp ebx, _KERNEL_VIRTUAL
    jae _syscall_amap_exit
    jecxz _syscall_amap_exit
    cmp edx, (_PROT_READ or _PROT_WRITE or _PROT_EXEC)
    ja _syscall_amap_exit
    cmp esi, (_AMAP_BIG or _AMAP_FIXED)
    ja _syscall_amap_exit
    _round_up ecx, _PAGE_FRAME_SIZE
    xor eax, eax
    mov al, _ALLOCATION_VIRTUAL
    test esi, _AMAP_BIG
    jz _syscall_amap_fixed
    or al, _ALLOCATION_PSE
    or dl, (1H shl ((bsf _PROT_EXEC) + 1H))
_syscall_amap_fixed:
    test esi, _AMAP_FIXED
    jz _syscall_amap_next
    or al, _ALLOCATION_HINT
_syscall_amap_next:
    mov edx, dword [_syscall_amap_table+edx*4H]
    xor esi, esi
    mov edi, _KERNEL_VIRTUAL
    call _map_virtual_address
    mov eax, (-ENOMEM)
    jc _syscall_amap_exit
    mov eax, ebx
_syscall_amap_exit:
    ret
_syscall_amap_table:
    dd _user_xd_ro_page
    dd _user_xd_rw_page
    dd _user_ro_page
    dd _user_rw_page
    dd _user_big_xd_ro_page
    dd _user_big_xd_rw_page
    dd _user_big_ro_page
    dd _user_big_rw_page
_syscall_amap_table_end:

_syscall_umap:
 ; in:
 ;  ebx - target address
 ;  ecx - length of the block address
    mov eax, (-EINVAL)
    jecxz _syscall_umap_exit
    mov esi, ebx
    mov edi, ecx
    call _userspace_sanitize
    mov eax, (-EINVAL)
    jc _syscall_umap_exit
    mov ebx, esi
    mov ecx, edi
    xor eax, eax
    mov al, _DEALLOCATION_VIRTUAL
    _round_up ecx, _PAGE_FRAME_SIZE
    call _unmap_virtual_address
    mov eax, (-EINVAL)
    jc _syscall_umap_exit
    xor eax, eax
_syscall_umap_exit:
    ret

_syscall_fork:
    mov ebp, dword [_current]
    call _switch_mapping_kernel
    call _create_process
    mov eax, (-ENOMEM)
    jc _syscall_fork_exit
    mov dword [ebx+_process.parent], ebp
    xor eax, eax
    mov dword [ebp+_process.allzmbs], eax
    mov eax, dword [ebp+_process.uid]
    mov dword [ebx+_process.uid], eax
    mov eax, dword [ebp+_process.sid]
    mov edx, dword [ebx+_process.sesdesc]
    mov dword [ebx+_process.sid], eax
    mov dword [ebx+_process.sesdesc], edx
    mov eax, dword [ebp+_process.ustck]
    mov edx, dword [ebp+_process.break]
    mov ecx, dword [ebp+_process.mnbrk]
    mov dword [ebx+_process.ustck], eax
    mov dword [ebx+_process.break], edx
    mov dword [ebx+_process.mnbrk], ecx
    ;mov eax, dword [ebp+_process.tty]
    ;mov dword [ebx+_process.tty], eax
    mov edi, ebx
    mov ecx, _process.siblings
    call _doubly_linked
    push ebx
    lea edx, dword [ebp+_process.childs]
    call _assign_list_esp
    mov ebx, edi
    mov eax, dword [ebp+_process.increment]
    mov dword [ebx+_process.increment], eax
    mov esi, dword [ebp+_process.mapping]
    mov edi, dword [ebx+_process.mapping]
    call _duplicate_mapping
    ;XXX
    ;mov eax, (-ENOMEM)
    ;jc _syscall_fork_exit
 
    mov eax, dword [ebp+_process.sesdesc]
    mov dword [ebx+_process.sesdesc], eax
   
    push ebx ebp
    mov ebx, dword [ebx+_process.pid]
    mov ecx, dword [ebp+_process.pgid]
    call _syscall_spgid
    ; mov eax, 0H
    ; jc _syscall_fork_exit
    pop ebp ebx

    mov edi, dword [ebx+_process.pgstck]
    mov esi, dword [ebp+_process.pgstck]
    mov ecx, _PAGE_FRAME_SIZE
    call _copy_string
    lea esi, [esp-4H]
    and esi, _PAGE_OFFSET_MASK
    or esi, dword [ebx+_process.pgstck]
    mov dword [esi], _syscall_fork_exit
    mov dword [ebx+_process.context], esi
    mov eax, dword [ebx+_process.pid]
    jmp _syscall_fork_exit+2H
_syscall_fork_exit:
    xor eax, eax
    ret

_syscall_exec:
 ; in:
 ;  ebx - code buffer (user pointer)
 ;  ecx - length code buffer (XXX check ecx = 0H)
 ; out: eax - 0H on success or some errno value
    push 0H ; kernel buffer address
    mov esi, ebx
    mov ebp, ecx
    call _userspace_sanitize
    mov eax, (-EINVAL)
    jc _syscall_exec_exit
    mov eax, ebp
    call _vmalloc
    jc _syscall_exec_memory
    mov ecx, ebp
    mov edi, eax
    call _copy_string
    mov dword [esp], eax
    call _switch_mapping_kernel
    mov eax, dword [_current]
    mov esi, dword [eax+_process.mapping]
    call _default_mapping
    mov eax, (-EFAULT)
    jc _syscall_exec_exit
    call _switch_mapping_user
 irp _kind*, _USER_CODE_VIRTUAL,_USER_STACK_VIRTUAL,_USER_SHELL_ARGUMENT_VIRTUAL
 {
    mov ebx, _kind
    xor ecx, ecx
    inc cl
  match =_USER_CODE_VIRTUAL, _kind
  \{
    mov edx, _user_rw_page
    mov ecx, ebp
    _round_up ecx, _PAGE_FRAME_SIZE
  \}
  match =_USER_STACK_VIRTUAL, _kind \{ mov edx, _user_xd_rw_page \}
  match =_USER_SHELL_ARGUMENT_VIRTUAL, _kind \{ mov edx, _user_rw_page \}
    xor eax, eax
    mov al, (_ALLOCATION_VIRTUAL or _ALLOCATION_HINT)
    call _map_virtual_address
    jc _syscall_exec_memory
 }
    mov esi, dword [esp]
    mov eax, esi
    mov edi, _USER_CODE_VIRTUAL
    mov ecx, ebp
    call _copy_string
    call _vfree
    jc _syscall_exec_memory
    mov ebx, _USER_CODE_VIRTUAL
    mov ecx, ebp
    mov edx, (_PROT_READ or _PROT_EXEC)
    call _syscall_mprot
    test eax, eax
    js _syscall_exec_exit
    mov ebx, dword [_current]
    mov esi, [ebx+_process.retframe]
    mov edi, esi
    xor ecx, ecx
    mov cl, _x86_register.trap
    call _clear_string ; avoid leak
    mov dword [ebx+_process.ustck], _USER_STACK_VIRTUAL
    mov dword [esi+_x86_register.eip], _USER_CODE_VIRTUAL
    mov word [esi+_x86_register.cs], _CODE_USER
    mov dword [esi+_x86_register.eflags], (_EFLAGS_AC or _EFLAGS_IF or _EFLAGS_RSVD)
    mov dword [esi+_x86_register.esp], _USER_SHELL_ARGUMENT_VIRTUAL
    mov word [esi+_x86_register.ss], _DATA_USER
    mov word [esi+_x86_register.ds], _DATA_USER
    mov word [esi+_x86_register.es], _DATA_USER
    add ebp, (_USER_CODE_VIRTUAL+(_PAGE_FRAME_SIZE-1H))
    and ebp, (not _PAGE_OFFSET_MASK)
    mov dword [ebx+_process.mnbrk], ebp
    mov dword [ebx+_process.break], ebp
    xor eax, eax
    jmp _syscall_exec_exit
_syscall_exec_memory:
    mov eax, (-ENOMEM)
_syscall_exec_exit:
    lea esp, [esp+4H]
    ret

_syscall_argcpy:
 ; note: copy the argument memory area from the parent to the child
    mov ebx, _USER_SHELL_ARGUMENT_VIRTUAL
    call _page_present
    jc _syscall_argcpy_notmap
    mov ebx, dword [_current]
    cmp dword [ebx+_process.pid], _INIT_PID
    mov eax, (-EFAULT)
    jbe _syscall_argcpy_exit
    mov ebp, dword [ebx+_process.parent]
    cmp ebp, dword [_initproc]
    jz _syscall_argcpy_notmap ; meaning the child has been reparented
    mov eax, dword [ebp+_process.mapping]
    xor edx, edx
    call _store_temporary_1
    test byte [_singleton.pae], 1H
    jz _syscall_argcpy_dump
    mov esi, (_PAE_TEMP_1_LINEAR_PDE + ((_USER_SHELL_ARGUMENT_VIRTUAL shr _PAE_PAGE_DIRECTORY_POINTER_SHIFT) shl 3H))
    call _load_entry
    test eax, _PE_PRESENT
    jz _syscall_argcpy_notmap
    call _store_temporary_1
_syscall_argcpy_dump:
    mov ebx, _USER_SHELL_ARGUMENT_VIRTUAL
    call _convert_virtual_volatile
    mov esi, ebx
    call _linear_make_single_recursive
    test byte [ebx], _PE_PRESENT
    jz _syscall_argcpy_notmap
    test byte [ebx], _PDE_SIZE
    jnz _syscall_argcpy_notmap
    test byte [esi], _PE_PRESENT
    jz _syscall_argcpy_notmap
    call _load_entry
    call _store_temporary_1
    mov esi, _TEMP_1_LINEAR_PDE
    test byte [_singleton.pae], 1H
    jz $+7H
    mov esi, _PAE_TEMP_1_LINEAR_PDE
    mov edi, _USER_SHELL_ARGUMENT_VIRTUAL
    mov ecx, _PAGE_FRAME_SIZE
    call _copy_string
    xor eax, eax
    jmp _syscall_argcpy_exit
_syscall_argcpy_notmap:
    mov eax, (-EEXIST)
_syscall_argcpy_exit:
    jmp _clear_temporary_1

_syscall_maccess:
 ; in:
 ;  ebx - memory target
 ;  ecx - memory size
    call _userspace_sanitize
    mov eax, (-EFAULT)
    jc _syscall_maccess_exit
    xor eax, eax
_syscall_maccess_exit:
    ret

_enable_timer:
    test byte [_singleton.apic], 1H
    ret

_PIT_CONTROL_BINARY_COUNT = 0H
_PIT_CONTROL_BCD_COUNT = 1H
_PIT_CONTROL_MODE_0 = 0H
_PIT_CONTROL_MODE_1 = (1B shl 1H)
_PIT_CONTROL_MODE_2 = (010B shl 1H)
_PIT_CONTROL_MODE_3 = (011B shl 1H)
_PIT_CONTROL_MODE_4 = (100B shl 1H)
_PIT_CONTROL_MODE_5 = (101B shl 1H)
_PIT_CONTROL_RL_LATCH = 0H
_PIT_CONTROL_RL_MSB = (010B shl 4H)
_PIT_CONTROL_RL_LSB = (001B shl 4H)
_PIT_CONTROL_RL_LSB_MSB = (011B shl 4H) 
_PIT_CONTROL_SELECT_0 = 0H
_PIT_CONTROL_SELECT_1 = (001B shl 6H)
_PIT_CONTROL_SELECT_2 = (010B shl 6H)
_IBM_8253_CHANNEL_0 = 040H
_IBM_8253_CHANNEL_1 = 041H
_IBM_8253_CHANNEL_2 = 042H
_IBM_8253_CONTROL_WORD = 043H
_IBM_8253_CLCK = 01234DEH
_configure_8253:
 ; in: XXX Hz
    mov al, (_PIT_CONTROL_SELECT_0 or _PIT_CONTROL_RL_LSB_MSB or _PIT_CONTROL_MODE_2 or _PIT_CONTROL_BINARY_COUNT)
    out _IBM_8253_CONTROL_WORD, al
    mov ax, (_IBM_8253_CLCK / 064H)
    out _IBM_8253_CHANNEL_0, al
    mov al, ah
    out _IBM_8253_CHANNEL_0, al
    ret

_pit_irq:
    jmp _reschedule

include "kbd.inc"

_enable_a20:
 ; note: in other word, disable A20M
    mov al, _SYSTEM_ENABLE_A20
    out _SYSTEM_PORT, al
    ret

_disable_a20:
    ret

_keyboard_irq:
    call _keyboard_driver
    jc _keyboard_irq_exit
    xor cl, cl
    not cl
    cmp ah, _KEY_LEFT_GUI
    jz _keyboard_irq_window
    add cl, 2H
    cmp ah, _KEY_RIGHT_GUI
    jz _keyboard_irq_window
    cmp al, _ESCAPE
    jnz _keyboard_irq_send
    call _keyboard_driver_ctrl_pressed
    jc _keyboard_irq_send
 rept _TELETYPE_COUNT i:1H
 {
    cmp ah, _ESC_F#i
    jz _keyboard_irq_index
 }
    jmp _keyboard_irq_send
_keyboard_irq_index:
    mov dl, ah
    sub dl, _ESC_F1
    jmp _keyboard_irq_switch
_keyboard_irq_window:
    mov ebx, dword [_current_teletype]
    mov dl, byte [ebx+_teletype.id]
    add dl, cl
    jns _keyboard_irq_adjust
    xor dl, dl
_keyboard_irq_adjust:
    cmp dl, _TELETYPE_COUNT
    jb _keyboard_irq_switch
    mov dl, (_TELETYPE_COUNT - 1H)
_keyboard_irq_switch:
    movzx eax, dl
    mov ebx, dword [_teletype_table+eax*4H]
    call _teletype_switch
    jmp _keyboard_irq_exit
_keyboard_irq_send:
 ; in: eax - keycode:character in the lower 16-bit
    test al, al
    jz _keyboard_irq_exit
    mov ebx, dword [_current_teletype]
    call _teletype_internal_buffer_full
    jc _keyboard_irq_exit
    mov edx, eax
    call _keyboard_irq_input
    test edx, edx
    jz _keyboard_irq_exit
    call _keyboard_irq_local
    mov eax, ebx
    call _wakeup_channel
_keyboard_irq_exit:
    ret

_keyboard_irq_input:
 ; in:
 ;  ebx - teletype object pointer
 ;   dx - keycode:character
 ; out:
 ;   al = 0FFH when the (newline,veol) has been entered (only relevant in canonical mode)
 ;   dx - keycode:character updated
 ; preserves: ebx, ecx, esi, edi, ebp
    movzx eax, word [ebx+_teletype.termios.iflag]
    test al, ISTRIP
    jz _keyboard_irq_input_strip
    and dl, (not 080H)
_keyboard_irq_input_strip:
    test eax, IUCLC
    jz _keyboard_irq_input_newline
    cmp dl, 041H
    jc _keyboard_irq_input_newline
    cmp dl, 05BH
    jae _keyboard_irq_input_newline
    xor dl, 020H
_keyboard_irq_input_newline:
    cmp dl, 00AH
    jnz _keyboard_irq_input_carriage
    test al, INLCR
    jz _keyboard_irq_input_carriage
    mov dx, ((_KEY_ENTER shl 8H) or 00DH)
_keyboard_irq_input_carriage:
    cmp dl, 00DH
    jnz _keyboard_irq_input_flow
    test al, IGNCR
    jnz _keyboard_irq_input_exit
    test eax, ICRNL
    jz _keyboard_irq_input_flow
    mov dx, 00AH
_keyboard_irq_input_flow:
    test eax, IXON
    jz _keyboard_irq_input_post
    cmp dl, byte [ebx+_teletype.termios.vstop]
    jz _keyboard_irq_input_handle
    cmp dl, byte [ebx+_teletype.termios.vstart]
    jnz _keyboard_irq_input_post
_keyboard_irq_input_handle:
    xor edx, edx
_keyboard_irq_input_post:
    cmp dl, 00AH
    jz _keyboard_irq_input_exit
    cmp dl, byte [ebx+_teletype.termios.veol]
_keyboard_irq_input_exit:
    call _convert_zero_carry
    salc
    ret

_keyboard_irq_local:
 ; in:
 ;   al - newline,veol has been pressed
 ;  ebx - teletype object pointer
 ;   dx - keycode:character
 ; preserves: ebx, ebp
    movzx ecx, word [ebx+_teletype.termios.lflag]
    test cl, ICANON
    jz _keyboard_irq_local_raw
    cmp dl, byte [ebx+_teletype.termios.veof]
    jz _keyboard_irq_local_eoi
    test al, al
    jns _keyboard_irq_local_canonical
_keyboard_irq_local_eoi:
    mov byte [ebx+_teletype.eoi], (not 0H)
    mov ax, word [ebx+_teletype.index]
    mov word [ebx+_teletype.ceidx], ax
    jns _keyboard_irq_local_exit
    inc word [ebx+_teletype.ceidx]
_keyboard_irq_local_canonical:
    test cl, ECHOE
    jz _keyboard_irq_local_kill
    cmp dl, byte [ebx+_teletype.termios.verase]
    jnz _keyboard_irq_local_werase
    xor ecx, ecx
    inc cl
    jmp _teletype_erase_internal
_keyboard_irq_local_werase:
    cmp dl, byte [ebx+_teletype.termios.vwerase]
    jnz _keyboard_irq_local_kill
    test ecx, IEXTEN
    jz _keyboard_irq_local_raw
    movzx ecx, word [ebx+_teletype.index]
    test ecx, ecx
    jz _keyboard_irq_local_exit
    mov esi, dword [ebx+_teletype.input]
    lea esi, [esi+ecx-1H]
    xor edx, edx
    std
_keyboard_irq_local_werase_loop:
    lodsb
    cmp al, 041H
    jb _keyboard_irq_local_werase_finish
    cmp al, 05AH
    jbe _keyboard_irq_local_werase_update
    cmp al, 061H
    jb _keyboard_irq_local_werase_finish
    cmp al, 07AH
    ja _keyboard_irq_local_werase_finish
_keyboard_irq_local_werase_update:
    mov dl, 1H
    loop _keyboard_irq_local_werase_loop 
_keyboard_irq_local_werase_finish:
    test dl, dl
    jnz _keyboard_irq_local_werase_next
    loop _keyboard_irq_local_werase_loop
_keyboard_irq_local_werase_next:    
    cld
    sub cx, word [ebx+_teletype.index]
    neg cx
    jmp _teletype_erase_internal
_keyboard_irq_local_kill:
    test cl, ECHOK
    jz _keyboard_irq_local_newline
    cmp dl, byte [ebx+_teletype.termios.vkill]
    jnz _keyboard_irq_local_newline
    movzx ecx, word [ebx+_teletype.index]
    jmp _teletype_erase_internal
_keyboard_irq_local_newline:
    test cl, ECHONL
    jz _keyboard_irq_local_raw
    cmp dl, 00AH
    jz _keyboard_irq_local_prepare
_keyboard_irq_local_raw:
    test cl, ECHO
    jz _keyboard_irq_local_signal
_keyboard_irq_local_prepare:
    mov ax, dx
    xor edx, edx
    test ecx, ECHOCTL
    jz _keyboard_irq_local_print
    mov edx, (not ((1H shl _TELETYPE_TABULATION) or (1H shl _TELETYPE_NEWLINE)))
_keyboard_irq_local_print:
    mov esi, ecx
    mov edi, _TELETYPE_UPDATE_CURSOR
    call _teletype_write_character
    jc _keyboard_irq_local_exit
    mov ecx, esi
    mov dx, ax
_keyboard_irq_local_signal:
    test cl, ISIG
    jz _keyboard_irq_local_insert
    cmp dl, byte [ebx+_teletype.termios.vintr]
    mov eax, SIGINT
    jz _teletype_send_signal
    cmp dl, byte [ebx+_teletype.termios.vquit]
    mov eax, SIGQUIT
    jz _teletype_send_signal
    cmp dl, byte [ebx+_teletype.termios.vsusp]
    mov eax, SIGTSTP
    jz _teletype_send_signal
_keyboard_irq_local_insert:
    mov ax, dx
    call _teletype_insert_character
    cmp al, _ESCAPE
    jnz _keyboard_irq_local_exit
    movzx dx, ah
    jmp _keyboard_irq_local_raw
_keyboard_irq_local_exit:
    ret

_fpu_irq:
    clts
    xor al, al
    out _COPROCESSOR_ERROR, al
    wait
    ;fnclex
    ;jmp _fpu_error
    ret

irp _kind*,_com2_irq,_com1_irq,_lpt2_irq,_floppy_irq,_lpt1_irq,_rtc_irq,_vga_retrace_irq,_mouse_irq,_hdd_irq,_ign_irq
{
_kind:
    ret
}

include "signal.inc"

_idt_reset:
    pushd 0H
    pushw 0H
    lidt fword [esp]
    add esp, 6H
    ret

_reboot_system:
    test byte [_singleton.apic], 1H
    jz _reboot_system_legacy
    ; XXX send INIT IPI
_reboot_system_legacy:
    mov al, _SYSTEM_FAST_RESET
    out _SYSTEM_PORT, al
    call _idt_reset ; if it's don't work
    ud2

_power_off:
    mov ax, 05307H
    mov bx, 1H
    mov cx, 3H
    call _system_bios
    jmp _panic

rept _IDT_ENTRY i:0H
{
_interrupt_stub_#i:
 if ((i <> 8H) & (i <> 00AH) & (i <> 00BH) & (i <> 00CH) & (i <> _EXCEPTION_GENERAL_PROTECTION) & (i <> _EXCEPTION_PAGE_FAULT) & (i <> 011H))
    pushd 0H
 end if
    pushd i
    jmp _interrupt_handler
}

align 8H
_spurious_interrupt_gate DT_gte _DE_PRESENT or _DPL0 or _386_INTERRUPT_GATE, 0H, _CODE_KERNEL, _spurious_interrupt
_spurious_interrupt:
    iret

include "vm86.inc"

_debug:
    mov ebx, dword [_current]
    mov ebx, dword [ebx+_process.retframe]
    mov edx, dr6
    test edx, (_DR6_BD or _DR6_BS or _DR6_BT) ; General detect, eflags[TF], task switch
    jnz _debug_adjust
    or dword [ebx+_x86_register.eflags], _EFLAGS_RF
_debug_adjust:
    test edx, _DR6_BD
    jz _debug_reset
    ;XXX
_debug_reset:
    mov eax, _DR6
    mov dr6, eax
_debug_int3:
    ret

irp _kind*, _divide_error,_coprocessor_error,_fpu_error,_simd_error
{
_kind:
    mov eax, SIGFPE
    jmp _send_signal_current
}

irp _kind*, _overflow,_bound,_invalid_tss,_general_protection
{
_kind:
    mov eax, SIGSEGV
    jmp _send_signal_current
}

_undefined_opcode:
    mov eax, SIGILL
    jmp _send_signal_current

_alignement_check_message string "#BAA: " ; bad alignement access
_alignement_check:
; XXX
    mov ebx, dword [_current]
    mov byte [ebx+_process.extsig], SIGBUS
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _alignement_check_message
    mov edx, _alignement_check_message.sizeof
    call _syscall_write
    ;mov ebx, dword [_current]
    ;jmp _default_action_core_already
    jmp $

irp _kind*, _segment,_stack_segment
{
_kind:
    mov eax, SIGBUS
    jmp _send_signal_current
}

_device_not_available:
    mov esi, dword [_current]
    mov al, byte [esi+_process.fltctx.active]
    test al, al
    jnz _device_not_available_retreive
    not al
    mov byte [esi+_process.fltctx.active], al
    mov eax, _FXSAVE_TOTAL
    call _kmalloc
    ;jc _device_not_available_finish
    ;jc _panic XXX
    mov dword [esi+_process.fltctx.save], eax
    mov edi, eax
    mov esi, _fpu_init
    mov ecx, _FXSAVE_TOTAL
    call _copy_string
    jmp _device_not_available_clear
_device_not_available_retreive:
    mov eax, dword [esi+_process.fltctx.save]
_device_not_available_clear:
    clts
    fxrstor [eax]
_device_not_available_finish:
    ret

irp _kind*, _nmi,_double_fault,_intel_rsvd,_machine_check,_virtualization_error,_control_protection,_vmm_error,_security_error
{
_kind:
    jmp _panic
}

_sysenter_entry:
    mov ecx, ebp
    mov edx, _vdso_sysenter
    sysexit

_call_gate_entry:
 ; in: eax - syscall vector
 ; preserves: eax, ebx, ecx, edx, esi, edi, ebp
 ; note:
 ;  transform this stack layout (left) into the right one:
 ;  +-----------+       +-----------+
 ;  |        ss |       |        ss |
 ;  |-----------|       |-----------|
 ;  |       esp |       |       esp |
 ;  |-----------|  -->  |-----------|
 ;  |        cs |       |    eflags |
 ;  |-----------|       |-----------|
 ;  |       eip |       |        cs |
 ;  +-----------+       |-----------|
 ;                      |       eip |
 ;                      +-----------+
    pushf
    push eax ebx
    mov eax, dword [esp+8H]
    mov ebx, dword [esp+00CH]
    xchg eax, dword [esp+010H]
    mov dword [esp+00CH], eax
    mov dword [esp+8H], ebx
    pop ebx eax
    jmp _interrupt_stub_48

_interrupt_handler:
    pushd gs fs es ds
    pusha
    pushd _DATA_KERNEL _DATA_KERNEL
    popd ds es
    cld
    test byte [_singleton.smap], 1H
    jz _interrupt_handler_switch
    stac
_interrupt_handler_switch:
    test dword [esp+_x86_register.eflags], _EFLAGS_VM
    jnz _interrupt_handler_monitor
    cmp dword [esp+_x86_register.trap], _SYSCALL_ENTRY
    jz _interrupt_handler_syscall
    mov edx, dword [esp+_x86_register.trap]
    cmp edx, _interrupt_handler_table.size
    jae _interrupt_handler_exit
    mov dword [_interrupt_handler_eoi], (_nothing - _interrupt_handler_after)
    cmp edx, _INTEL_RESERVED_INT
    jb _interrupt_handler_invoke
    ;test byte [_singleton.apic], 1H
    ;jz _interrupt_handler_legacy
    ;mov dword [_interrupt_handler_eoi], (_local_apic_eoi - _interrupt_handler_after)
    ;jmp _interrupt_handler_invoke   
_interrupt_handler_legacy:
    mov eax, _8259_eoi_master
    cmp edx, (_INTEL_RESERVED_INT + _IBM_PIC_IRQ_LINE)
    jb _interrupt_handler_8259_eoi
    mov eax, _8259_eoi_master_slave
_interrupt_handler_8259_eoi:
    call eax
_interrupt_handler_invoke:
    call dword [_interrupt_handler_table+edx*4H]
    call 0H
 label _interrupt_handler_eoi dword at ($ - 4H)
_interrupt_handler_after:
    jmp _interrupt_handler_signal
_interrupt_handler_syscall:
    call _syscall_dispatcher
    mov ebx, dword [_current]
    mov ebx, dword [ebx+_process.retframe]
    mov dword [ebx+_x86_register.eax], eax
    jmp _interrupt_handler_signal
_interrupt_handler_monitor:
    call _vm86_monitor
    jnc _interrupt_handler_exit
    jmp _vm86_monitor_hlt
_interrupt_handler_signal:
    call _switch_mapping_user
    call _handle_signal
    jc _segmentation_core
_interrupt_handler_exit:
    popa
    pop ds es fs gs
    add esp, 8H
    iretd

_interrupt_service_table _interrupt_handler_table
    _ist _divide_error
    _ist _debug
    _ist _nmi
    _ist _debug_int3
    _ist _overflow
    _ist _bound
    _ist _undefined_opcode
    _ist _device_not_available
    _ist _double_fault
    _ist _coprocessor_error
    _ist _invalid_tss
    _ist _segment
    _ist _stack_segment
    _ist _general_protection
    _ist _page_fault
    _ist _intel_rsvd
    _ist _fpu_error
    _ist _alignement_check
    _ist _machine_check
    _ist _simd_error
    _ist _virtualization_error
    _ist _control_protection
 rept ((01CH - 016H) + 1H) { _ist _intel_rsvd, ignore }
    _ist _vmm_error
    _ist _security_error
    _ist _intel_rsvd
  assert ((($ - _interrupt_handler_table) shr 2H) = _INTEL_RESERVED_INT)
    _ist _pit_irq
    _ist _keyboard_irq
    _ist _ign_irq, ignore
    _ist _com2_irq
    _ist _com1_irq
    _ist _lpt2_irq
    _ist _floppy_irq
    _ist _lpt1_irq
    _ist _rtc_irq
    _ist _vga_retrace_irq
    _ist _ign_irq, ignore
    _ist _ign_irq, ignore
    _ist _mouse_irq
    _ist _fpu_irq
    _ist _hdd_irq
    _ist _ign_irq, ignore
  assert ((($ - _interrupt_handler_table) shr 2H) = _SYSCALL_ENTRY)
end _interrupt_service_table

use64

_swapgs_needed:
 ; note:
 ;  Test the RPL (in this context CPL) in ss or cs to see if the cpu was interrupted in RING 0H.
 ;  RPL 1H, 2H are not checked because they are not used.
   ;mov ax, ss
    mov ax, cs
    test ax, 011B
    jz _swapgs_needed_exit
    swapgs
_swapgs_needed_exit:
    ret

use32

_addressing_real_current:
    mov ebx, dword [_current]
_addressing_real:
 ; in: ebx - current process pointer (aka [_current])
 ; preserves: ebx, esi, edi, ebp
 ; note: if [_PAE_PDPT_RECURSIVE_VIRTUAL] = _pae_real_pgdir, _addressing_real lock mapreal automatically
    push esi edi
    cmp byte [ebx+_process.mapreal], 0H
    jnz _addressing_real_exit
    mov byte [ebx+_process.mapreal], (not 0H)
    call _addressing_real_invlpg
    mov edi, _PAE_PDPT_RECURSIVE_VIRTUAL
    mov esi, _pae_real_pgdir
    test byte [_singleton.pae], 1H
    jnz _addressing_real_extract
    mov edi, _PAGE_DIRECTORY_LINEAR
    mov esi, _real_pgtable
_addressing_real_extract:
    mov eax, dword [edi]
    mov ecx, eax
    and ecx, (not _PAGE_OFFSET_MASK)
    cmp ecx, esi
    jnz _addressing_real_next
    mov byte [ebx+_process.mapreal], 0H
    jmp _addressing_real_exit
_addressing_real_next:
    xor edx, edx
    test byte [_singleton.pae], 1H
    jz _addressing_real_dump    
    mov edx, dword [_PAE_PDPT_RECURSIVE_VIRTUAL+4H]
_addressing_real_dump:
    mov dword [ebx+_process.lwreal], eax
    mov dword [ebx+_process.hgreal], edx
    mov eax, esi
    or eax, (_PE_READ_WRITE or _PE_PRESENT)
    xor edx, edx
    test byte [_singleton.pae], 1H
    jnz _addressing_real_dump_pae
    or al, _VIRTUAL_REAL_PROTECTION
    mov edi, _PAGE_DIRECTORY_LINEAR
    call _store_entry
    jmp _addressing_real_exit
_addressing_real_dump_pae:
    mov edi, _PAE_PDPT_RECURSIVE_VIRTUAL
    call _store_entry
    mov edi, _PAE_PTE_RECURSIVE_BASE_ITSELF
    call _store_entry
    mov edi, ebx
    call _refresh_pae_pdptr
    mov ebx, edi
    or dword [_PAE_PDPT_RECURSIVE_VIRTUAL], _VIRTUAL_REAL_PROTECTION
_addressing_real_exit:
    pop edi esi
    ret
_addressing_real_revert_current:
    mov ebx, dword [_current]
_addressing_real_revert:
 ; in: ebx - current process pointer (aka [_current])
 ; preserves: ebx, edi, esi, ebp
    push edi
    cmp byte [ebx+_process.lckreal], 0H
    jnz _addressing_real_revert_exit
    cmp byte [ebx+_process.mapreal], 0H
    jz _addressing_real_revert_exit
    mov byte [ebx+_process.mapreal], 0H
    call _addressing_real_invlpg
    mov eax, dword [ebx+_process.lwreal]
    mov edx, dword [ebx+_process.hgreal]
    test byte [_singleton.pae], 1H
    jnz _addressing_real_revert_pae
    mov edi, _PAGE_DIRECTORY_LINEAR
    call _store_entry
    jmp _addressing_real_revert_exit
_addressing_real_revert_pae:
    mov edi, _PAE_PDPT_RECURSIVE_VIRTUAL
    call _store_entry
    mov edi, _PAE_PTE_RECURSIVE_BASE_ITSELF
    call _store_entry
    call _refresh_pae_pdptr
_addressing_real_revert_exit:
    pop edi
    ret
_addressing_real_invlpg:
 ; preserves: ebx, edx, esi, edi, ebp
    xor eax, eax
    mov ecx, ((_MAX_REAL_ADDRESS shr _PAGE_TABLE_SHIFT) + 1H)
_addressing_real_invlpg_loop:
    invlpg [eax]
    add eax, _PAGE_FRAME_SIZE
    loop _addressing_real_invlpg_loop
    test byte [_singleton.pae], 1H
    jnz _addressing_real_invlpg_pae
    invlpg [_RECURSIVE_VIRTUAL]
    jmp _addressing_real_invlpg_exit
_addressing_real_invlpg_pae:
    invlpg [_PAE_PTE_RECURSIVE_BASE]
_addressing_real_invlpg_exit:
    ret

_DATUM_UNREAL       = 08000H
_START_UNREAL       = 07C00H
_STACK_UNREAL       = 06F00H
_REAL_WRAPAROUND    = (1H shl 8H)
_execute_real:
 ; in:
 ;  [esp+4H] - target int to call
 ;  argument are in GRP (Segment selector must not be used)
 ; out:
 ;  result are in GPR (Segment selector are discarded)
 ;  cf - set if no enough memory (in this case not real mode int is executed)
 ; note:
 ;  all register on entry are passed as-in to the real mode int.
 ;  to see the eflags images on return from real mode int, consult _process.vmflgs.
    push eax ebx ecx edx
    call _clear_cr0_am
    ;test byte [esp+014H], _REAL_WRAPAROUND
    mov ebx, dword [_current]
    call _addressing_real
    test byte [ebx+_process.vm86], 1H
    jnz _execute_real_transition
    mov eax, _PAGE_FRAME_SIZE
    call _vmalloc
    jc _execute_real_exit
    mov ebx, dword [_current]
    mov byte [ebx+_process.vm86], 1H
    add eax, _PAGE_FRAME_SIZE
    mov dword [ebx+_process.vstack], eax
    mov dword [_tss_vm86.esp0], eax
    sub eax, _vm86_x86_register.sizeof
    mov dword [ebx+_process.vmframe], eax
_execute_real_transition:
    mov bx, _TSS_VM86
    call _switch_tss
    mov al, byte [esp+014H]
    mov byte [_START_UNREAL], _INT
    mov byte [_START_UNREAL+1H], al
    mov byte [_START_UNREAL+2H], _HLT
    mov ebx, dword [_current]
    lea edx, [esp+8H]
    mov dword [ebx+_process.context], edx
    mov eax, dword [ebx+_process.vstack]
    pop edx ecx ebx esp
    xchg esp, eax
    push 0H ; ES
    push 0H ; DS
    push 0H ; FS
    push 0H ; GS
    push 0H ; SS
    push _STACK_UNREAL
    push (_EFLAGS_VM or _EFLAGS_RSVD)
    push 0H ; CS
    push _START_UNREAL
    iretd
_execute_real_terminate:
    call _enable_a20
    mov ebx, dword [_current]
    call _express_alignement_mask
    mov esi, dword [ebx+_process.context]
    mov esp, dword [ebx+_process.vmframe]
    mov edx, dword [esp+_vm86_x86_register.register.eflags]
    mov dword [ebx+_process.vmflgs], edx
    mov edi, esi
 irp _kind*, ebx,eax
 {
    mov eax, dword [esp+_vm86_x86_register.register.#_kind]
    stosd
 }
    mov dword [esp+_vm86_x86_register.register+_PUSHA_TOTAL], esi ; point to the next byte after popa
    call _addressing_real_revert
    popa
    pop esp
    mov bx, _TSS
    call _switch_tss
    jmp _execute_real_exit+2H
_execute_real_exit:
    pop edx ecx
    pop ebx eax
    retn 4H

_DESCRIPTOR_ACCESS = 5H
_switch_tss:
 ; in: bx - new TSS selector
 ; preserves: ebx, ecx, edx, esi, edi, ebp
    str eax
    xor byte [eax+_GDT+_DESCRIPTOR_ACCESS], _TSS_BUSY
    ltr bx
    ret

_video_bios:
    push 010H
    call _execute_real
    ret

_system_bios:
    push 015H
    call _execute_real
    ret

_INTEL_RESERVED_INT = 020H
_IBM_PIC_MASTER_COMMAND = 020H
_IBM_PIC_MASTER_DATA = (_IBM_PIC_MASTER_COMMAND + 1H)
_IBM_PIC_SLAVE_COMMAND = 0A0H
_IBM_PIC_SLAVE_DATA = (_IBM_PIC_SLAVE_COMMAND + 1H)
_IBM_PIC_IRQ_LINE = 8H
_8259_ICW1_ICW4 = 1B
_8259_ICW1_SINGLE = 010B
_8259_ICW1_INTERVAL_4 = 100B
_8259_ICW1_LEVEL = 01000B
_8259_ICW1_ALWAYS = 10000B
_8259_ICW4_86_88 = 1B
_8259_ICW4_AUTO_EOI = 010B
_8259_ICW4_BUFFER_MODE_SLAVE = 01000B
_8259_ICW4_BUFFER_MODE_MATSER = 01100B
_8259_ICW4_SPECIAL_NESTED = 10000B
_8259_EOI = 020H
_8259_enable:
 ; in: eax - start vector for IRQ (INTR line)
 ; preserves: esi, edi, ebp
    movzx eax, al
    mov bl, al
    in al, _IBM_PIC_MASTER_DATA
    mov cl, al
    in al, _IBM_PIC_SLAVE_DATA
    mov dl, al
    mov al, (_8259_ICW1_ALWAYS or _8259_ICW1_ICW4)
    out _IBM_PIC_MASTER_COMMAND, al
    out _IBM_PIC_SLAVE_COMMAND, al
    mov al, bl
    and al, (not 011B)
    out _IBM_PIC_MASTER_DATA, al
    add al, _IBM_PIC_IRQ_LINE
    out _IBM_PIC_SLAVE_DATA, al
    mov al, 000000100B
    out _IBM_PIC_MASTER_DATA, al
    mov al, 010B
    out _IBM_PIC_SLAVE_DATA, al
    mov al, _8259_ICW4_86_88
    out _IBM_PIC_MASTER_DATA, al
    out _IBM_PIC_SLAVE_DATA, al
    mov al, cl
    out _IBM_PIC_MASTER_DATA, al    
    mov al, dl
    out _IBM_PIC_SLAVE_DATA, al
    ret

_8259_disable:
 ; note: mask all IRQ
    xor al, al
    not al
    out _IBM_PIC_MASTER_DATA, al
    out _IBM_PIC_SLAVE_DATA, al
    ret

_8259_eoi_master:
    mov al, _8259_EOI
    out _IBM_PIC_MASTER_COMMAND, al
    ret

_8259_eoi_master_slave:
    call _8259_eoi_master
    out _IBM_PIC_SLAVE_COMMAND, al
    ret

_local_apic_eoi:
    mov dword [_PAE_LOCAL_APIC+_LOCAL_EOI_REGISTER], 0H
    ret

enum & _SWAP_IDT_ASSIGN_GATE
_swap_idt_vector_backup: $DT_null
_set_and_swap_idt_vector:
    call _swap_idt_vector
    xor edx, edx
_swap_idt_vector:
 ; in:
 ;  eax - vector to swap or assign
 ;  edx - gate aligned to 8H-byte boundaries + flags
 ; out: cf - set if eax does not contain a valid vector
 ; preserves: eax, ebx, ecx, edx, esi, edi, ebp
    push esi edi
    cmp eax, _IDT_ENTRY
    cmc
    jc _swap_idt_vector_exit
    shl eax, (bsr DT_gte.sizeof)
    test dl, _SWAP_IDT_ASSIGN_GATE
    lea esi, [edx-_SWAP_IDT_ASSIGN_GATE]
    jnz _swap_idt_vector_assign
    lea esi, [_IDT+eax]
    mov edi, _swap_idt_vector_backup
 rept 2H { movsd }
    lea esi, [_swap_idt+eax]
    lea edi, [_IDT+eax]
 rept 2H { movsd }
    mov esi, _swap_idt_vector_backup
_swap_idt_vector_assign:
    lea edi, [_swap_idt+eax]
 rept 2H { movsd }
    shr eax, (bsr DT_gte.sizeof)
_swap_idt_vector_exit:
    pop edi esi
    ret

align 8H
_apic_error_gate DT_gte _DE_PRESENT or _DPL0 or _386_INTERRUPT_GATE, 0H, _CODE_KERNEL, _apic_error_handler
_apic_error_handler:
    xor eax, eax
    lea ebx, [eax+_LOCAL_APIC_ACCESS_WRITE]
    mov ecx, _ERROR_STATUS_REGISTER
    call _local_apic_access_register
    mov bl, _LOCAL_APIC_ACCESS_READ
    call _local_apic_access_register
    mov esi, eax
    xor eax, eax
    mov bl, _LOCAL_APIC_ACCESS_WRITE
    call _local_apic_access_register
    call _local_apic_access_register ; back-to-back write
    test esi, _ESR_SEND_ILLEGAL_VECTOR
    ;XXX
_apic_error_handler_exit:
    ret

_descriptor_table _GDT
    $DT_null
    _kernel_code_segment DT_dte _DE_D or _DE_G, _DE_PRESENT or _DPL0 or _DE_EXECUTABLE or _DE_READABLE, 0H, 00FFFFFH
    _kernel_data_segment DT_dte _DE_B or _DE_G, _DE_PRESENT or _DPL0 or _DE_WRITABLE, 0H, 00FFFFFH
    _user_code_segment DT_dte _DE_D or _DE_G, _DE_PRESENT or _DPL3 or _DE_EXECUTABLE or _DE_READABLE, 0H, 00FFFFFH
    _user_data_segment DT_dte _DE_B or _DE_G, _DE_PRESENT or _DPL3 or _DE_WRITABLE, 0H, 00FFFFFH
    _tss_segment DT_ste _DE_PRESENT or _DPL0 or _386_TSS, _tss, ((_tss_end - _tss) - 1H)
    _call_gate DT_gte _DE_PRESENT or _DPL3 or _386_CALL_GATE, 0H, _CODE_KERNEL, _call_gate_entry
    _tss_vm86_segment DT_ste _DE_PRESENT or _DPL0 or _386_TSS, _tss_vm86, ((_tss_vm86_end - _tss_vm86) - 1H)
end _descriptor_table

_descriptor_table _GDT_64
    $DT_null
    _kernel_code_64_segment DT_dte _DE_L, _DE_PRESENT or _DPL0 or _DE_EXECUTABLE, 0H, 0H
    _user_code_64_segment DT_dte _DE_L, _DE_PRESENT or _DPL3 or _DE_EXECUTABLE, 0H, 0H
    _user_code_compatibility DT_dte _DE_D or _DE_G, _DE_PRESENT or _DPL3 or _DE_EXECUTABLE or _DE_READABLE, 0H, 00FFFFFH
    _user_data_compatibility DT_dte _DE_B or _DE_G, _DE_PRESENT or _DPL3 or _DE_WRITABLE, 0H, 00FFFFFH
    _tss_64_segment Long_DT_ste _DE_PRESENT or _DPL0 or _386_TSS, _tss_64, ((_tss_64_end - _tss_64) - 1H)
end _descriptor_table

_SYSCALL_ENTRY          = 030H
_APIC_LINT0_ENTRY       = 031H
_APIC_LINT1_ENTRY       = 032H
_APIC_ERROR_ENTRY       = 033H
_APIC_SPURIOUS_ENTRY    = 034H

_descriptor_table _IDT
  rept _IDT_ENTRY i:0H
  {
      _cdpl = _DPL0
      _gate = _386_INTERRUPT_GATE
      if (i = _SYSCALL_ENTRY)
          _cdpl = _DPL3
          ;_gate = _386_TRAP_GATE
      end if
      _vector_#i DT_gte _DE_PRESENT or _cdpl or _gate, 0H, _CODE_KERNEL, _interrupt_stub_#i
  }
end _descriptor_table

_descriptor_table _swap_idt
    rept _IDT_ENTRY i:0H { _swap_vector_#i: db DT_gte.sizeof dup 0H }
end _descriptor_table

;_descriptor_table _IDT_64
;end _descriptor_table

_tss _TSS_32 0H, _kernel_stack, _DATA_KERNEL, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H,\
        0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, (_tss_bitmap - _tss)
_tss_os_specific:
_tss_interrupt:
_tss_bitmap:
_tss_end:

_tss_vm86 _TSS_32 0H, _kernel_stack, _DATA_KERNEL, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H,\
    0H, 0H, 0H, 0H, 0H, 0H, 0H, 0H, (_tss_vm86_bitmap - _tss_vm86)
_tss_vm86_os_specific:
_tss_vm86_interrupt: ; interrupt redirection 
    db 020H dup 0H
_tss_vm86_bitmap: ; io permission bitmap
    db 02000H dup 0H
    db 0FFH
_tss_vm86_end:

_tss_64 _TSS_64 _kernel_stack, 0H, 0H, _kernel_ist1, _kernel_ist2, _kernel_ist3, _kernel_ist4,\
    _kernel_ist5, _kernel_ist6, _kernel_ist7, (_tss_64_bitmap - _tss_64)
_tss_64_os_specific:
_tss_64_bitmap:
_tss_64_end:

_DEFAULT_KERNEL_STACK = 040H ; cache line size on most platform
align (_DEFAULT_KERNEL_STACK)
db 0H dup _DEFAULT_KERNEL_STACK
_kernel_stack:

define _IST_TOTAL 7H
rept _IST_TOTAL i:1H
{
    db 0H dup _DEFAULT_KERNEL_STACK
    _kernel_ist#i:
}

align _FXSAVE_TOTAL
_fpu_init: db _FXSAVE_TOTAL dup 0H
_default_mxcsr: dd (_MXCSR_PM or _MCXSR_UM or _MXCSR_OM or _MXCSR_ZM or _MXCSR_DM or _MXCSR_IM)

align 4H
_test_bitmap_table _bitmap 0H

macro _extract [_title*]
{
common local _base, _payload
forward
    virtual _title
        _base = $$
    end virtual
    _title#_#payload:
    repeat _title#.sizeof
        load _payload byte from _title:(_base + (% - 1H))
        db _payload
    end repeat
}

include "help.inc"
include "usertest.inc"
include "segvtest.inc"
include "hostname.inc"
include "reboot.inc"
include "shutdown.inc"
include "copyright.inc"
include "uid.inc"
include "kill.inc"
include "uname.inc"
include "color.inc"
include "resolution.inc"
include "clear.inc"
include "sigint.inc"
include "client.inc"
include "server.inc"
include "sockpoc.inc"
include "sqrt.inc"
include "md5.inc"
include "bomb.inc"
include "invopcode.inc"
include "showpid.inc"
include "print.inc"
include "shell.inc"
include "login.inc"
include "init.inc"
include "vdso.inc"

_abc:

_extract _init, _vdso

_debugs _abc, _def, _interrupt_handler


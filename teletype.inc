
enum & _SET_FONT_FORCE
_teletype_set_font:
 ; in:
 ;  ebx - teletype object pointer
 ;  ecx - flags (force change font even if it's the same)
 ;  esi - fonts object pointer
 ; out: cf - set when width/height are not power of two
 ; preserves: ebx, edi, esi, ebp
    push edi
    cmp ecx, (_SET_FONT_FORCE + 1H)
    cmc
    jc _teletype_set_font_exit
    test cl, _SET_FONT_FORCE
    jnz _teletype_set_font_force
    cmp dword [ebx+_teletype.fonts], esi
    jz _teletype_set_font_exit
_teletype_set_font_force:
    mov eax, esi
    lea edi, [ebx+_teletype.fonts]
    mov ecx, _fonts.sizeof
    call _copy_string
    mov esi, eax
    movzx eax, byte [esi+_fonts.width]
    call _is_power_two
    jc _teletype_set_font_exit
    movzx eax, byte [esi+_fonts.height]
    call _is_power_two
    jc _teletype_set_font_exit
    movzx eax, byte [esi+_fonts.width]
    movzx edx, byte [esi+_fonts.height]
    bsf eax, eax
    bsf edx, edx
    mov byte [esi+_fonts.btposw], al
    mov byte [esi+_fonts.btposh], dl
    mov cl, al
    mov ax, word [_current_modeinfo.x_resolution]
    shr ax, cl
    stc
    jz _teletype_set_font_exit
    mov word [ebx+_teletype.xgrid], ax
    mov cl, dl
    mov dx, word [_current_modeinfo.y_resolution]
    shr dx, cl
    stc
    jz _teletype_set_font_exit
    mov word [ebx+_teletype.ygrid], dx
    movzx eax, word [_current_modeinfo.bytes_scanline]
    shl eax, cl
    mov dword [ebx+_teletype.scroll], eax
    call _teletype_clear
_teletype_set_font_exit:
    pop edi
    ret

_teletype_remap_frame_buffer:
 ; in: ebx - teletype object pointer
 ; preserves: eax, ebx, edx, edi, ebp
    push eax ebx edx edi
    cmp ebx, dword [_current_teletype]
    jnz _teletype_remap_frame_buffer_exit
    mov esi, dword [_current]
    cmp byte [esi+_process.refresh], 0H
    mov byte [esi+_process.refresh], 0H
    jz _teletype_remap_frame_buffer_exit
    xor ecx, ecx
    mov cl, _REGEN_4MB_PAGE
    test byte [_singleton.pae], 1H
    jz _teletype_remap_frame_buffer_remap
    shl ecx, ((_PAGE_DIRECTORY_SHIFT - _PAGE_TABLE_SHIFT) - (_PAE_PAGE_DIRECTORY_SHIFT - _PAE_PAGE_TABLE_SHIFT))
_teletype_remap_frame_buffer_remap:
    xor eax, eax
    mov al, (_DEALLOCATION_VIRTUAL or _DEALLOCATION_PSE or _DEALLOCATION_SHARING)
    mov ebx, dword [ebx+_teletype.video]
    and ebx, (not _PSE_OFFSET_MASK)
    call _unmap_virtual_address
    jc _teletype_remap_frame_buffer_exit
    xor eax, eax
    mov al, (_ALLOCATION_VIRTUAL or _ALLOCATION_PSE)
    call _allocate_kernel_frame
_teletype_remap_frame_buffer_exit:
    pop edi edx ebx eax
    ret

_teletype_buffer_target:
 ; in: ebx - teletype object pointer
 ; out:
 ;  edi - target buffer (regen or video)
 ;   zf - set when the video video ram is selected
 ; preserves: eax, ebx, ecx, edx, esi, ebp
    mov edi, dword [ebx+_teletype.video]
    cmp ebx, dword [_current_teletype]
    jz _teletype_buffer_target_exit
    mov edi, dword [ebx+_teletype.regen]
_teletype_buffer_target_exit:
    ret

_teletype_clear:
 ; in: ebx - teletype object pointer
 ; out: cf - set on error
 ; preserves: ebx, ecx, esi, edi, ebp
    push ecx esi edi
    xor eax, eax
    mov byte [ebx+_teletype.cursor], al
    mov word [ebx+_teletype.xlinear], ax
    mov word [ebx+_teletype.ylinear], ax
    mov word [ebx+_teletype.xsaved], ax
    mov word [ebx+_teletype.ysaved], ax
    call _teletype_buffer_target
    jnz _teletype_clear_perform
    mov eax, dword [_current]
    cmp byte [eax+_process.refresh], 0H ; if the cursor is already set jump for set the cursor
    jz _teletype_clear_perform
    call _teletype_remap_frame_buffer
_teletype_clear_perform:
    mov ecx, dword [_vbe_frame_amount]
    call _clear_string
    mov byte [ebx+_teletype.cursor], (not 0H) ; and set the cursor to the top left
    call _teletype_redraw_cursor
    pop edi esi ecx
    ret

_teletype_erase_character:
 ; in:
 ;  ebx - teletype object pointer
 ;  ecx - count of position to move backward
 ; preserves: ebx, esi, ebp
    jecxz _teletype_erase_character_exit
_teletype_erase_character_loop:
    mov al, _TELETYPE_BACKSPACE
    xor edx, edx
    call _teletype_write_character
    jc _teletype_erase_character_exit
    mov al, 020H
    xor edi, edi
    call _teletype_write_character
    jc _teletype_erase_character_exit
    loop _teletype_erase_character_loop
_teletype_erase_character_exit:
    ret

_teletype_set_color:
 ; in:
 ;  eax - forground color
 ;  ebx - teletype object pointer
 ;  edx - background color
    mov dword [ebx+_teletype.foregnd], eax
    mov dword [ebx+_teletype.backgnd], edx 
    ret

_teletype_redraw_cursor:
 ; in: ebx - teletype object pointer
 ; out: cf - set on error
 ; preserves: ebx, ebp
    cmp byte [ebx+_teletype.cursor], 0H
    jz _teletype_redraw_cursor_exit
    xor eax, eax
    mov edx, _teletype_write_character_cursor
    call _teletype_write_character_foreach
_teletype_redraw_cursor_exit:
    ret

_teletype_update_cursor:
 ; in:
 ;  ebx - teletype object pointer
 ;  ebp - predicate direction pointer
 ; out:
 ; preserves: ebx, ecx, esi, edi, ebp
    push ecx esi edi
    call _teletype_redraw_cursor
    jc _teletype_update_cursor_exit
    call ebp
    call _teletype_redraw_cursor
_teletype_update_cursor_exit:
    pop edi esi ecx
    ret

_teletype_internal_buffer_full:
 ; in: ebx - teletype object pointer
 ; out: cf - set if overflow
    cmp word [ebx+_teletype.index], _PAGE_FRAME_SIZE
    jmp _convert_zero_carry

_teletype_reset_canonical:
    mov word [ebx+_teletype.ceidx], 0H
    mov byte [ebx+_teletype.eoi], 0H
    ret

_teletype_switch:
 ; in: ebx - target teletype object pointer
 ; preserves: eax, ebx, ebp
    push ebp
    mov ebp, dword [_current_teletype]
    cmp ebx, ebp
    jz _teletype_switch_exit
    mov esi, dword [ebp+_teletype.video]
    mov edi, dword [ebp+_teletype.regen]
    mov ecx, dword [_vbe_frame_amount]
    call _copy_string
    mov esi, dword [ebx+_teletype.regen]
    mov edi, dword [ebx+_teletype.video]
    mov ecx, dword [_vbe_frame_amount]
    call _copy_string
    mov dword [_current_teletype], ebx
_teletype_switch_exit:
    pop ebp
    ret

enum & _TELETYPE_UPDATE_CURSOR
_teletype_write_character:
 ; in:
 ;   al - target character
 ;  ebx - teletype object pointer
 ;  edx - control character mask (only useful when al is a control character)
 ;  edi - flags
 ; out:
 ;   cf - set on error
 ; preserves: eax, ebx, ecx, esi, edi, ebp
    push eax ecx esi ebp
    push edi    ; flags
    push 0H     ; is printable ?
    call _teletype_remap_frame_buffer
    jc _teletype_write_character_exit
    cmp edi, (_TELETYPE_UPDATE_CURSOR + 1H)
    cmc
    jc _teletype_write_character_exit
    mov ebp, _teletype_write_character_forward
    cmp al, 07FH
    jae _teletype_write_character_special
    cmp al, 020H
    jae _teletype_write_character_printable
_teletype_write_character_special:
    mov edi, _TELETYPE_UPDATE_CURSOR
    mov dword [esp+4H], edi
    cmp al, 07FH
    jae _teletype_write_character_escape
    mov cl, al
    mov ebp, 1H
    shl ebp, cl
    and ebp, edx
    jz _teletype_write_character_control
_teletype_write_character_escape:
    lea esi, [eax+040H]
    and esi, 07FH
    mov al, 05EH
    call _teletype_write_character
    jc _teletype_write_character_exit
    mov eax, esi
    call _teletype_write_character
    jmp _teletype_write_character_exit
_teletype_write_character_control:
    mov byte [esp], (not 0H)
    cmp al, _TELETYPE_BACKSPACE
    mov ebp, _teletype_direction_backward
    jz _teletype_write_character_printable
    cmp al, _TELETYPE_TABULATION
    jz _teletype_write_character_tabulation
    cmp al, _TELETYPE_NEWLINE
    mov ebp, _teletype_write_character_newline
    jz _teletype_write_character_printable
    cmp al, _TELETYPE_CARRIAGE
    mov ebp, _teletype_write_character_carriage
    clc
    jnz _teletype_write_character_exit
_teletype_write_character_printable:
    mov esi, dword [ebx+_teletype.fonts.source]
    sub al, 020H
    movzx eax, al
    mov cl, byte [ebx+_teletype.fonts.btposh]
    shl eax, cl
    add esi, eax
    call _teletype_redraw_cursor
    jc _teletype_write_character_exit
_teletype_write_character_display:
    cmp byte [esp], 0H
    jnz _teletype_write_character_invoke
    xor eax, eax
    mov al, (_TELETYPE_WRITE_TEMPLATE or _TELETYPE_SAVE_ALL)
    mov edx, _teletype_write_character_glyph
    call _teletype_write_character_foreach
    jc _teletype_write_character_exit
_teletype_write_character_invoke:
    test byte [esp+4H], _TELETYPE_UPDATE_CURSOR
    jz _teletype_write_character_redraw
    call ebp
    jc _teletype_write_character_exit
_teletype_write_character_redraw:
    call _teletype_redraw_cursor
    jmp _teletype_write_character_exit
_teletype_write_character_tabulation:
    movzx ecx, byte [ebx+_teletype.tabulation]
    mov al, 020H
    mov edi, _TELETYPE_UPDATE_CURSOR
    test ecx, ecx
    jnz _teletype_write_character_tabulation_loop
    inc cl
_teletype_write_character_tabulation_loop:
    call _teletype_write_character
    jc _teletype_write_character_exit
    loop _teletype_write_character_tabulation_loop
_teletype_write_character_exit:
    lea esp, [esp+4H]
    pop edi ebp esi ecx eax
    ret

_teletype_write_character_forward:
 ; preserves: ebx, esi, edi, ebp
    call _teletype_direction_forward
    jnc _teletype_write_character_forward_exit+3H ; skip all pop
    mov word [ebx+_teletype.xlinear], 0H
_teletype_write_character_forward_nextline:
    push esi edi ebp
    call _teletype_direction_downward
    jnc _teletype_write_character_forward_exit
    xor eax, eax
    xor edx, edx
    call _teletype_write_character_position
    jc _teletype_write_character_forward_exit
    mov esi, edi
    xor eax, eax
    movzx edx, word [ebx+_teletype.ylinear]
    call _teletype_write_character_position
    jc _teletype_write_character_forward_exit
    mov ebp, edi
    sub edi, esi
    mov ecx, edi
    xor eax, eax
    xor edx, edx
    inc dl
    call _teletype_write_character_position
    jc _teletype_write_character_forward_exit
    xchg esi, edi
    call _copy_string
    mov edi, ebp
    mov ecx, dword [ebx+_teletype.scroll]
    call _clear_string 
_teletype_write_character_forward_exit:
    pop ebp edi esi
    ret

_teletype_write_character_newline:
    call _teletype_write_character_forward_nextline
    test byte [ebx+_teletype.termios.oflag], OPOST
    jnz _teletype_write_character_carriage
    ret
_teletype_write_character_carriage:
    mov word [ebx+_teletype.xlinear], 0H
    ret

_teletype_write_character_position:
 ; in: 
 ;  eax - x linear in the framebuffer
 ;  ebx - teletype object pointer
 ;  edx - y linear in the framebuffer
 ; out: edi - framebuffer location
 ; preserves: ebx, ecx, esi, ebp
    push ecx
    mov cl, byte [ebx+_teletype.fonts.btposh]
    shl edx, cl
    movzx ecx, word [_current_modeinfo.bytes_scanline]
    imul edx, ecx
    jc _teletype_write_character_position_exit
    mov cl, byte [ebx+_teletype.fonts.btposw]
    shl eax, cl
    call _bsf_bits_pixel
    shl eax, cl    
    add eax, edx
    call _teletype_buffer_target
    add edi, eax
_teletype_write_character_position_exit:
    pop ecx
    ret

enum & _TELETYPE_WRITE_TEMPLATE, _TELETYPE_SAVE_ALL
_teletype_write_character_foreach:
 ; in:
 ;  eax - write foreach flags
 ;  ebx - teletype object pointer
 ;  edx - predicate to call on each character scanline (functor must preserve all register except edi)
 ; out: cf - set on error
 ; preserves: eax, ebx, edx, ebp
 ; note:
 ;  on predicate call all register must be preserved except eax when _TELETYPE_WRITE_TEMPLATE is specified
 ;  cf is set also to indicate if a match occurs character '@' in fonts.inc
    push eax ebp edx
    cmp eax, ((_TELETYPE_WRITE_TEMPLATE or _TELETYPE_SAVE_ALL) + 1H)
    cmc
    jc _teletype_write_character_foreach_exit 
    movzx eax, word [ebx+_teletype.xlinear]
    movzx edx, word [ebx+_teletype.ylinear]
    call _teletype_write_character_position
    jc _teletype_write_character_foreach_exit
    movzx ecx, byte [ebx+_teletype.fonts.width]
    movzx ebp, byte [ebx+_teletype.fonts.height]
_teletype_write_character_foreach_loop:
    xor eax, eax
    lea edx, [ecx-1H]
    test byte [esp+8H], _TELETYPE_WRITE_TEMPLATE
    jz _teletype_write_character_foreach_btst
    lodsb
_teletype_write_character_foreach_btst:
    test byte [esp+8H], _TELETYPE_SAVE_ALL
    jnz _teletype_write_character_foreach_save_all
    bt ax, dx
    call dword [esp]
    jmp _teletype_write_character_foreach_decrement
_teletype_write_character_foreach_save_all:
    bt ax, dx
    pusha
    call dword [esp+_PUSHA_TOTAL]
    mov dword [esp+_PUSHA_EDI], edi
    popa
_teletype_write_character_foreach_decrement:
    dec edx
    test byte [esp+8H], _TELETYPE_WRITE_TEMPLATE
    test edx, edx
    jns _teletype_write_character_foreach_btst
    dec ebp
    jz _teletype_write_character_foreach_exit
    movzx eax, word [_current_modeinfo.bytes_scanline]
    lea edi, [edi+eax]
    mov edx, ecx
    call _bsf_bits_pixel
    mov eax, edx
    shl eax, cl
    mov ecx, edx
    sub edi, eax
    jmp _teletype_write_character_foreach_loop
_teletype_write_character_foreach_exit:
    pop edx ebp eax
    ret

_teletype_write_character_glyph:
    mov eax, dword [ebx+_teletype.backgnd]
    jnc _teletype_write_character_glyph_store
    mov eax, dword [ebx+_teletype.foregnd]
_teletype_write_character_glyph_store:
    cmp byte [ebx+_teletype.legacy], 0H
    jz $+5H
    stosb
    jmp $+3H
    stosd
    ret

_CURSOR_COLOR_RGB = _RGB_WHITE
_CURSOR_COLOR_VGA = _VGA_WHITE
_teletype_write_character_cursor:
    mov eax, dword [ebx+_teletype.foregnd]
    cmp byte [edi], al
    jnz _teletype_write_character_cursor_color
    cmp byte [ebx+_teletype.legacy], 0H
    jnz _teletype_write_character_cursor_exit
    cmp dword [edi], eax
    jz _teletype_write_character_cursor_exit
_teletype_write_character_cursor_color:
    mov eax, dword [ebx+_teletype.backgnd]
    cmp byte [ebx+_teletype.legacy], 0H
    jz _teletype_write_character_cursor_vbe
    cmp byte [edi], _CURSOR_COLOR_VGA
    jz _teletype_write_character_cursor_exit
    xor eax, eax
    mov al, _CURSOR_COLOR_VGA
    jmp _teletype_write_character_cursor_exit
_teletype_write_character_cursor_vbe:
    cmp dword [edi], _CURSOR_COLOR_RGB
    jz _teletype_write_character_cursor_exit
    mov eax, _CURSOR_COLOR_RGB
_teletype_write_character_cursor_exit:
    jmp _teletype_write_character_glyph_store

_teletype_direction_downward:
 ; out: cf - set when overflow
    mov ax, word [ebx+_teletype.ygrid]
    dec ax
    cmp word [ebx+_teletype.ylinear], ax
    cmc
    jc _teletype_direction_downward_exit
    inc word [ebx+_teletype.ylinear]
_teletype_direction_downward_exit:
    ret

_teletype_direction_forward:
 ; out: cf - set when overflow
    mov ax, word [ebx+_teletype.xgrid]
    dec ax
    cmp word [ebx+_teletype.xlinear], ax
    cmc
    jc _teletype_direction_forward_exit
    inc word [ebx+_teletype.xlinear]
_teletype_direction_forward_exit:
    ret

_teletype_direction_upward:
    cmp word [ebx+_teletype.ylinear], 0H
    jz _teletype_direction_upward_exit
    dec word [ebx+_teletype.ylinear]
_teletype_direction_upward_exit:
    ret

_teletype_direction_backward:
    cmp word [ebx+_teletype.xlinear], 0H
    jz _teletype_direction_backward_exit
    dec word [ebx+_teletype.xlinear]
_teletype_direction_backward_exit:
    ret

_teletype_direction_reset:
    mov word [ebx+_teletype.xlinear], 0H
    mov word [ebx+_teletype.ylinear], 0H
    ret

_teletype_erase_internal:
 ; in:
 ;  ebx - teletype object pointer
 ;  ecx - count of byte to delete
 ; out: cf - set on error
 ; preserves: ebx
    jecxz _teletype_erase_internal_exit
    cmp word [ebx+_teletype.index], 0H
    jz _teletype_erase_internal_exit
    movzx esi, word [ebx+_teletype.index]
    cmp ecx, esi
    cmova ecx, esi
    dec esi    
    add esi, dword [ebx+_teletype.input]
_teletype_erase_internal_loop:
    std
    lodsb
    cld
    mov ebp, ecx
    xor ecx, ecx
    cmp al, _TELETYPE_TABULATION
    mov cl, 4H
    jz _teletype_erase_internal_backspace
    cmp al, 020H
    jb _teletype_erase_internal_special
    cmp al, 07FH
    jae _teletype_erase_internal_special
    mov cl, 1H
    jnz _teletype_erase_internal_backspace
_teletype_erase_internal_special:
    xor cl, cl
    test dword [ebx+_teletype.termios.lflag], ECHOCTL
    jz _teletype_erase_internal_backspace
    mov cl, 2H
_teletype_erase_internal_backspace:
    test dword [ebx+_teletype.termios.lflag], ECHO
    jz teletype_erase_internal_update
    call _teletype_erase_character
    jc _teletype_erase_internal_exit
teletype_erase_internal_update:
    dec word [ebx+_teletype.index]
    mov ecx, ebp
    loop _teletype_erase_internal_loop
_teletype_erase_internal_exit:
    ret

_teletype_insert_character:
 ; in:
 ;   al - byte wanted to be inserted
 ;  ebx - teletype object pointer
 ; preserves: eax, ebx, ecx, edx, esi, ebp
    call _teletype_internal_buffer_full
    jc _teletype_insert_character_exit
    movzx edi, word [ebx+_teletype.index]
    add edi, dword [ebx+_teletype.input]
    stosb
    inc word [ebx+_teletype.index]
    clc
_teletype_insert_character_exit:
    ret

_teletype_send_signal:
 ; in:
 ;  eax - signal kind
 ;  ebx - teletype object pointer
 ; out: cf - set if bad signal or teletype not a controling terminal and not have a foreground group
 ; preserves: ebx, esi, edi, ebp 
 ; note: send the signal to all the process in the "foreground" group
    push ebx esi ebp
    cmp byte [ebx+_teletype.control], 0H
    jz _teletype_send_signal_exit
    cmp byte [ebx+_teletype.fground], 0H
    jz _teletype_send_signal_exit
    mov ebp, eax
    mov eax, dword [ebx+_teletype.grpdesc]
    lea eax, [eax+_process_group_descriptor.prclist]
    xor ecx, ecx
    mov cl, _process.pgroup
    xor edx, edx
    mov dl, (_LIST_FORWARD or _LIST_SAVE_ALL)
    mov esi, _send_signal_process_group_iterate
    call _find_list
_teletype_send_signal_exit:
    cmc
    pop ebp esi ebx
    ret

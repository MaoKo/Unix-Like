
_BITMAP_UNIT = 4H
assert ((bsf _BITMAP_UNIT) = (bsr _BITMAP_UNIT))
struct _bitmap _size*
    .next:  dd (.table)
    .last:  dd ((.table + (_size)) - _BITMAP_UNIT)
    .free:  dd ((_size) shl 3H)
    .table: db (_size) dup (not 0H)
ends

_bitmap_search:
 ; in:
 ;  eax - bitmap pointer
 ;  ebx - start of bitmap dword index where to count, 0H if _bitmap.next is desired
 ;  ecx - count of consecutive 1B to search
 ;  edx -   end of bitmap dword index where to count, 0H if _bitmap.last is desired
 ;  esi - (>0H) when aligned to the lsb of ecx (useless if ecx = 1H)
 ; out:
 ;  ebx - cf not set, bitmap dword index where the sequence of 1B reside
 ;  edx - cf not set, index in the byte where the first 1B occurs
 ;   cf - set if not found
 ; preserves: eax, ecx, edi, esi, ebp
    push esi edi ebp ecx
    test ecx, ecx
    jz _bitmap_search_carry
    test esi, esi
    mov esi, 1H
    jz _bitmap_search_position
    bsf esi, ecx
    xchg esi, ecx
    xor edi, edi
    inc edi
    shl edi, cl
    mov ecx, esi
    mov esi, edi
_bitmap_search_position:
    call _bitmap_search_sanitize
    jc _bitmap_search_carry+1H
    cmp ebx, dword [eax+_bitmap.next]
    ja _bitmap_search_specialized
    cmp edx, dword [eax+_bitmap.last]
    jnz _bitmap_search_specialized
    cmp ecx, dword [eax+_bitmap.free]
    ja _bitmap_search_carry
    jmp _bitmap_search_next
_bitmap_search_specialized:
    push ebx edx
    call _bitmap_bit_count
    pop edx ebx
    cmp ecx, dword [esp]
    jb _bitmap_search_carry+1H
_bitmap_search_next:
    xor edx, edx
    mov ecx, edx
    jmp _bitmap_search_scan
_bitmap_search_loop:
    lea edi, [esi-1H]
    and ecx, edi
    sub edi, ecx
    jz _bitmap_search_reset
    mov ecx, edi
    call _bitmap_search_proceed
    jc _bitmap_search_carry+1H
    loop $-7H
_bitmap_search_reset:
    xor ecx, ecx
_bitmap_search_advance:
    call _bitmap_search_proceed
    jc _bitmap_search_carry+1H
_bitmap_search_scan:
    bt dword [ebx], edx
    jnc _bitmap_search_loop
    test ecx, ecx
    jnz _bitmap_search_counter
    mov edi, edx
_bitmap_search_counter:
    inc ecx
    cmp ecx, dword [esp] 
    jb _bitmap_search_advance
    lea ecx, [ecx+edi-1H]
    shr ecx, 3H
    and cl, (not (_BITMAP_UNIT - 1H))
    sub ebx, ecx
    mov edx, edi
    clc
    jmp _bitmap_search_carry+1H
_bitmap_search_carry:
    stc
    pop ecx ebp edi esi
    ret
_bitmap_search_proceed:
    inc edx
    cmp edx, (_BITMAP_UNIT shl 3H)
    jb _bitmap_search_sanitize_exit
    xor edx, edx
_bitmap_search_proceed_advance:
    add ebx, _BITMAP_UNIT
_bitmap_search_proceed_overflow:
    cmp ebx, ebp
    cmova ebx, ebp
    ja _bitmap_search_sanitize_exit
    jmp _bitmap_search_sanitize_exit-1H
_bitmap_search_sanitize:
    lea ebp, [eax+_bitmap.table]
    test ebx, ebx 
    jnz _bitmap_search_sanitize_first
    mov ebx, dword [eax+_bitmap.next]
_bitmap_search_sanitize_first:
    cmp ebx, ebp
    jb _bitmap_search_sanitize_exit+1H
    test edx, edx
    jnz _bitmap_search_sanitize_second
    mov edx, dword [eax+_bitmap.last]
    jmp _bitmap_search_sanitize_ensure
_bitmap_search_sanitize_second:
    cmp edx, dword [eax+_bitmap.last]
    ja _bitmap_search_sanitize_exit
_bitmap_search_sanitize_ensure:
    cmp ebx, edx
    ja _bitmap_search_sanitize_exit
    mov ebp, edx
    stc
_bitmap_search_sanitize_exit:
    cmc
    ret

enum _BITMAP_RESET, _BITMAP_SET
_bitmap_update:
 ; in:
 ;  eax - bitmap pointer
 ;  ebx - bitmap dword index where the sequence of 1B reside
 ;  ecx - count of consecutive bit to update
 ;  edx - index in the byte where the first 1B occurs
 ;  edi - action to take
 ; out:
 ;  edx - the total number of bit changed when cf = 0H
 ;   cf - invalid action parameter or ebx overflow directly
 ; preserves: eax, ebx, ecx, edi, esi, ebp
    push ebx ecx esi ebp 0H
    jecxz _bitmap_update_exit
    mov ebp, dword [eax+_bitmap.last]
    call _bitmap_update_validity
    jc _bitmap_update_carry+1H
    cmp edi, _BITMAP_SET 
    ja _bitmap_update_carry
    jnz _bitmap_update_sanitize
    cmp ebx, dword [eax+_bitmap.next]
    jae _bitmap_update_sanitize
    mov dword [eax+_bitmap.next], ebx
_bitmap_update_sanitize:
    push eax
    xor eax, eax
    clc
_bitmap_update_loop:
    jc _bitmap_udpate_next
    mov esi, _bitmap_update_bit_switch
    cmp ecx, (_BITMAP_UNIT shl 3H)
    jb _bitmap_update_call
    mov esi, _bitmap_update_switch
    sub ecx, ((_BITMAP_UNIT shl 3H) - 1H)
    add edx, (_BITMAP_UNIT shl 3H)
_bitmap_update_call:
    call dword [esi+edi*4H]
    add eax, dword [esp+4H]
    xor esi, esi
    mov dword [esp+4H], esi ; reset the counter
    jc _bitmap_udpate_restore
    call _bitmap_search_proceed
    loop _bitmap_update_loop
_bitmap_udpate_next:
    mov edx, eax
    mov esi, eax
    clc
_bitmap_udpate_restore:
    pop eax
    jc _bitmap_update_carry+1H
    cmp edi, _BITMAP_RESET
    jnz _bitmap_update_exit
    mov ecx, ebx
    neg esi
_bitmap_update_remove:
    cmp ecx, dword [eax+_bitmap.next]
    jbe _bitmap_update_padding
    cmp dword [ecx], 0H
    jnz _bitmap_update_exit
    sub ecx, _BITMAP_UNIT
    jmp _bitmap_update_remove
_bitmap_update_padding:
    mov dword [eax+_bitmap.next], ebx
_bitmap_update_exit:
    add dword [eax+_bitmap.free], esi
    clc
    jmp _bitmap_update_carry+1H
_bitmap_update_carry:
    stc
    pop ecx ebp esi ecx ebx
    ret
_bitmap_update_bit_switch:
    dd _bitmap_update_bit_reset
    dd _bitmap_update_bit_set
_bitmap_update_switch:
    dd _bitmap_update_reset
    dd _bitmap_update_set
_bitmap_update_bit_reset:
    btr dword [ebx], edx
    jmp _bitmap_update_bit_return
_bitmap_update_bit_set:
    bts dword [ebx], edx
    cmc
_bitmap_update_bit_return:
    setc byte [esp+8H]
    ret
_bitmap_update_reset:
    call _bitmap_update_count_bit
    mov dword [ebx], 0H
    ret
_bitmap_update_set:
    call _bitmap_update_count_bit
    mov dword [ebx], not 0H
    sub byte [esp+8H], (_BITMAP_UNIT shl 3H)
    neg byte [esp+8H]
    ret
_bitmap_update_validity:
    call _bitmap_search_proceed_overflow
    jc _bitmap_update_validity_exit
    cmp edx, (_BITMAP_UNIT shl 3H)
    cmc
_bitmap_update_validity_exit:
    ret
_bitmap_update_count_bit:
    test byte [_singleton.popcnt], 1H
    jz _bitmap_update_count_bit_next
    popcnt esi, dword [ebx]
    mov dword [esp+8H], esi
    ret
_bitmap_update_count_bit_next:
    xor esi, esi
    xchg esi, ebx
 rept 4H i:0H
 {
    mov bl, byte [esi+i]
    mov bl, byte [_bitmap_bit_count_table+ebx]
    add byte [esp+00CH], bl
 }
    mov ebx, esi
_bitmap_update_count_bit_exit:
    ret

_bitmap_match:
 ; in:
 ;  eax - bitmap pointer
 ;  ebx - bitmap dword index where the sequence of 1B reside
 ;  ecx - count of consecutive bit to test
 ;  edx - index in the byte where the first 1B occurs
 ;  edi - kind of pattern to match
 ; out:
 ;   cf - set when match occurs
 ; preserves: eax, ebx, ecx, edx, esi, edi, ebp
    pushad
    mov ebp, dword [eax+_bitmap.last]
    call _bitmap_update_validity
    jc _bitmap_match_exit
    shl edi, 2H
    cmp edi, (_BITMAP_SET shl 2H)
    ja _bitmap_match_exit
_bitmap_match_loop:
    mov esi, _bitmap_match_bit_switch
    cmp ecx, (_BITMAP_UNIT shl 3H)
    jb _bitmap_match_call
    sub ecx, ((_BITMAP_UNIT shl 3H) - 1H)
    add edx, (_BITMAP_UNIT shl 3H)
    mov esi, _bitmap_match_switch
_bitmap_match_call:
    call dword [esi+edi]
    jnz _bitmap_match_exit
    call _bitmap_search_proceed
    jc _bitmap_match_exit
    loop _bitmap_match_loop
    stc
    jmp _bitmap_match_exit+1H
_bitmap_match_exit:
    clc
    popad
    ret
_bitmap_match_bit_switch:
    dd _bitmap_match_bit_reset
    dd _bitmap_match_bit_set
_bitmap_match_switch:   
    dd _bitmap_match_reset
    dd _bitmap_match_set
_bitmap_match_bit_set:
    bt dword [ebx], edx
    cmc
    jmp _bitmap_match_bit_reset+3H
_bitmap_match_bit_reset:
    bt dword [ebx], edx
    sbb esi, esi ; ZF = not CF
    ret
_bitmap_match_reset:
    cmp dword [ebx], 0H
    ret
_bitmap_match_set:
    cmp dword [ebx], not 0H
    ret

_bitmap_inverse:
 ; in:
 ;  eax - bitmap pointer
 ;  ebx - bitmap dword index where the sequence of 1B reside
 ;  ecx - count of consecutive bit to test
 ;  edx - index in the byte where the first 1B occurs
 ;  edi - kind of pattern to match in _bitmap_match
 ; out: cf - set when the target bitmap substring is not the inverse of the wanted result
 ; preserves: eax, ebx, ecx, esi, ebp
 ; note: call _bitmap_match first and if a match result then call _bitmap_update with the inverse of edi
    call _bitmap_match
    jnc _bitmap_inverse_exit
    not edi
    and edi, 1H
    call _bitmap_update
    jc _bitmap_inverse_exit+1H
    cmp ecx, edx
    clc
    jz _bitmap_inverse_exit+1H
_bitmap_inverse_exit:
    cmc
    ret

_bitmap_bit_count:
 ; in:
 ;  eax - bitmap pointer
 ;  ebx - start of bitmap dword index where to count, 0H if _bitmap.next is desired
 ;  edx -   end of bitmap dword index where to count, 0H if _bitmap.last is desired
 ; out:
 ;  ecx - the number of bit set in the bitmap.
 ;   cf - carry set when argument ill-formed or the bitmap was too huge
 ; preserves: eax, edi, esi, ebp
    push edi ebp
    call _bitmap_search_sanitize
    jc _bitmap_bit_count_carry+1H
    test byte [_singleton.popcnt], 1H
    setnz al
    movzx edi, al
    mov edi, dword [_bitmap_bit_count_switch+edi*4H]
    xor ecx, ecx
_bitmap_bit_count_loop:
    test dword [ebx], 0H
    jz _bitmap_bit_count_next
    call edi
    add ecx, edx
    jc _bitmap_bit_count_carry+1H
_bitmap_bit_count_next:
    call _bitmap_search_proceed_advance
    jnc _bitmap_bit_count_loop
_bitmap_bit_count_exit:
    clc
    jmp _bitmap_bit_count_exit+1H
_bitmap_bit_count_carry:
    stc
    pop ebp edi
    ret
_bitmap_bit_count_switch:
    dd _bitmap_bit_count_simple
    dd _bitmap_bit_count_feature
_bitmap_bit_count_simple:
    xor eax, eax
    xor edx, edx
 rept 4H i:0H
 {
    mov al, byte [ebx+i]
    add dl, byte [_bitmap_bit_count_table+eax]
 }
    ret
_bitmap_bit_count_feature:
    popcnt edx, dword [ebx]
    ret
_bitmap_bit_count_table:
    db 0H, 1H, 1H, 2H, 1H, 2H, 2H, 3H, 1H, 2H, 2H, 3H, 2H, 3H, 3H, 4H
    db 1H, 2H, 2H, 3H, 2H, 3H, 3H, 4H, 2H, 3H, 3H, 4H, 3H, 4H, 4H, 5H
    db 1H, 2H, 2H, 3H, 2H, 3H, 3H, 4H, 2H, 3H, 3H, 4H, 3H, 4H, 4H, 5H
    db 2H, 3H, 3H, 4H, 3H, 4H, 4H, 5H, 3H, 4H, 4H, 5H, 4H, 5H, 5H, 6H
    db 1H, 2H, 2H, 3H, 2H, 3H, 3H, 4H, 2H, 3H, 3H, 4H, 3H, 4H, 4H, 5H
    db 2H, 3H, 3H, 4H, 3H, 4H, 4H, 5H, 3H, 4H, 4H, 5H, 4H, 5H, 5H, 6H
    db 2H, 3H, 3H, 4H, 3H, 4H, 4H, 5H, 3H, 4H, 4H, 5H, 4H, 5H, 5H, 6H
    db 3H, 4H, 4H, 5H, 4H, 5H, 5H, 6H, 4H, 5H, 5H, 6H, 5H, 6H, 6H, 7H
    db 1H, 2H, 2H, 3H, 2H, 3H, 3H, 4H, 2H, 3H, 3H, 4H, 3H, 4H, 4H, 5H
    db 2H, 3H, 3H, 4H, 3H, 4H, 4H, 5H, 3H, 4H, 4H, 5H, 4H, 5H, 5H, 6H
    db 2H, 3H, 3H, 4H, 3H, 4H, 4H, 5H, 3H, 4H, 4H, 5H, 4H, 5H, 5H, 6H
    db 3H, 4H, 4H, 5H, 4H, 5H, 5H, 6H, 4H, 5H, 5H, 6H, 5H, 6H, 6H, 7H
    db 2H, 3H, 3H, 4H, 3H, 4H, 4H, 5H, 3H, 4H, 4H, 5H, 4H, 5H, 5H, 6H
    db 3H, 4H, 4H, 5H, 4H, 5H, 5H, 6H, 4H, 5H, 5H, 6H, 5H, 6H, 6H, 7H
    db 3H, 4H, 4H, 5H, 4H, 5H, 5H, 6H, 4H, 5H, 5H, 6H, 5H, 6H, 6H, 7H
    db 4H, 5H, 5H, 6H, 5H, 6H, 6H, 7H, 5H, 6H, 6H, 7H, 6H, 7H, 7H, 8H

enum _BITMAP_EXPAND_ZERO, _BITMAP_EXPAND_ONE
_bitmap_resize:
 ; in:
 ;  eax - bitmap pointer
 ;  ecx - new desired size
 ;  edi - desired action on expansion
 ; out:
 ;  edi - pointer to the byte just after the table expanded 
 ;   cf - set when ebx is not aligned on the _BITMAP_UNIT or edi ill formed
 ; preserves: eax, esi, ebp
    test ecx, (_BITMAP_UNIT - 1H)
    jnz _bitmap_resize_exit
    cmp edi, (_BITMAP_EXPAND_ONE + 1H)
    jae _bitmap_resize_exit
    mov edx, dword [eax+_bitmap.last]
    add edx, _BITMAP_UNIT
    mov ebx, edx
    sub edx, dword [eax+_bitmap.next]
    cmp ecx, edx
    jz _bitmap_resize_exit-1H
    sub ecx, edx
    jns _bitmap_resize_expand
    add dword [eax+_bitmap.last], ecx
    xor ebx, ebx
    mov edx, edx
    call _bitmap_bit_count
    mov dword [eax+_bitmap.free], ecx
    mov edi, dword [eax+_bitmap.last]
    add edi, _BITMAP_UNIT
    jmp _bitmap_resize_exit-1H
_bitmap_resize_expand:
    mov edx, eax
    xor eax, eax
    cmp edi, _BITMAP_EXPAND_ZERO
    mov edi, ebx
    mov ebx, 0H
    jz _bitmap_resize_perform
    lea ebx, [ecx*8H]
    dec eax
_bitmap_resize_perform:
    shr ecx, 2H
    rep stosd
    mov eax, edx
    lea edx, [edi-_BITMAP_UNIT]
    mov dword [eax+_bitmap.last], edx
    add dword [eax+_bitmap.free], ebx
    stc
_bitmap_resize_exit:
    cmc
    ret

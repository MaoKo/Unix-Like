
_ORIGINAL_TERMIOS = _USER_STACK_VIRTUAL

_SHELL_BUFFER_INTERNAL = 0DEAD000H
_USER_COMMAND_SIZE = 200H

struct _line_instance _buffer*, _length*
    .buffer:    db _buffer
    times       (_USER_COMMAND_SIZE - ($ - .buffer)) db 0H
    .length:    dd (_length)
ends

define _SIZE_HISTORY 010H
struct _shell_aggregate _buffer*, _length*, _cpybuf*, _cpylen*, _cursor*, _insert*, _hstste*, _hstidx*, _hstcnt*, _tmpbuf*, _tmplen*,\
        _ws_row*, _ws_col*, _ws_xpixel*, _ws_ypixel*, _pid*, _tty*, _wait*
    .command    _line_instance (_buffer), (_length)
    .copy       _line_instance (_cpybuf), (_cpylen)
    .cursor:    dd (_cursor)
    .insert:    db (_insert)
    .hstste:    db (_hstste)
    .hstidx:    db (_hstidx)
    .hstcnt:    db (_hstcnt)
    .hsttlb:
    rept        _SIZE_HISTORY i:0H \{ dd .history_\#i \}
    rept        _SIZE_HISTORY i:0H \{ .history_\#i _line_instance 0H, 0H \}
    .temporary  _line_instance (_tmpbuf), (_tmplen)
    .winsize    _winsize _ws_row, _ws_col, _ws_xpixel, _ws_ypixel
    .pid:       dd (_pid)
    .tty:       dd (_tty)
    .wait:      dd (_wait)
ends

virtual at _USER_CODE_VIRTUAL
_shell::
    ;rept 400H { nop }
    call _shell_allocate_struct
    call _shell_set_raw_mode
    xor eax, eax
    mov al, _SYSCALL_SIGNAL
    mov ebx, SIGHUP
    mov ecx, _shell_sighup
    int 030H
    xor eax, eax
    mov al, _SYSCALL_SIGNAL
    mov ebx, SIGINT
    mov ecx, _shell_sigint_handler
    int 030H
    xor eax, eax
    mov al, _SYSCALL_GPID
    int 030H
    mov dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.pid], eax
    call _shell_enable_history
_shell_restart:
    call _shell_prompt
_shell_loop:
    call _shell_read_one_character
    cmp al, 00DH
    jz _shell_process_command
    cmp al, 07FH
    jz _shell_remove
    cmp al, _ESCAPE
    jz _shell_escape
    cmp al, 1H ; ctrl-A
    mov ecx, _shell_begin_cursor
    jz _shell_predicate
    cmp al, 5H ; ctrl-E
    mov ecx, _shell_end_cursor
    jz _shell_predicate
    cmp al, 00BH ; ctrl-K
    mov ecx, _shell_truncate
    jz _shell_predicate
    cmp al, 016H ; ctrl-V
    jnz _shell_save
    mov eax, (_SHELL_BUFFER_INTERNAL + _shell_aggregate.copy.buffer)
    mov ebx, dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.copy.length]
    jmp _shell_insert
_shell_escape:
    call _shell_read_one_character
    cmp al, _ESC_LEFT_ARROW
    mov ecx, _shell_cursor_backward
    jz _shell_predicate
    cmp al, _ESC_RIGHT_ARROW
    mov ecx, _shell_cursor_forward
    jz _shell_predicate
    cmp al, _ESC_UP_ARROW
    mov ecx, _shell_move_up_history
    jz _shell_predicate
    cmp al, _ESC_DOWN_ARROW
    mov ecx, _shell_move_down_history
    jz _shell_predicate

    jmp _shell_loop
_shell_save:
    mov eax, (_SHELL_BUFFER_INTERNAL + _shell_aggregate.insert)
    xor ebx, ebx
    inc bl
_shell_insert:
    call _shell_command_insert
    jmp _shell_loop
_shell_predicate:
    call ecx
    jmp _shell_loop
_shell_remove:
    call _shell_command_remove
    jmp _shell_loop

_shell_process_command:
    call _shell_print_newline
    mov ecx, dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.command.length]
    mov edi, (_SHELL_BUFFER_INTERNAL + _shell_aggregate.command.buffer)
    call _shell_skip_whitespace
    jz _shell_process_command_validate
 irp _kind*, help,copyright,uid,uname,shutdown,reboot,hostname,fg,bg,resolution,clear,sigint,usertest,segvtest,kill,sockpoc,sqrt,md5,bomb,invopcode,showpid,print
 {
    mov eax, _shell_#_kind#.sizeof
    mov ebx, _#_kind#_payload
    mov esi, _shell_#_kind
    mov ebp, _#_kind#.sizeof
    call _shell_parse_command
    jnc _shell_process_command_validate
 }
    push _shell_process_command_validate
 irp _kind*, history,copy,exit
 {
    mov eax, _shell_#_kind#.sizeof
    mov esi, _shell_#_kind
    call _shell_word_compare
    jnc _shell_#_kind#_command
 }
    lea esp, [esp+4H]
    call _shell_command_unknown
_shell_process_command_validate:
    call _shell_save_history
    xor eax, eax
    mov ecx, [_SHELL_BUFFER_INTERNAL+_shell_aggregate.command.length]
    mov dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.command.length], eax
    mov dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.cursor], eax
    mov edi, _SHELL_BUFFER_INTERNAL+_shell_aggregate.command.buffer
    rep stosb
    jmp _shell_restart

_shell_set_raw_mode:
    xor eax, eax
    mov al, _SYSCALL_IOCTL
    mov ebx, _TELETYPE_CURRENT
    mov ecx, TCGETS
    lea edx, [esp-_termios.sizeof]
    int 030H
    and dword [edx+_termios.iflag], (not (ICRNL or ISTRIP or IXON))
    and dword [edx+_termios.oflag], (not OPOST)
    and dword [edx+_termios.lflag], (not (ECHO or ICANON or IEXTEN or ISIG))
    mov byte [edx+_termios.vmin], 0H
    xor eax, eax
    mov al, _SYSCALL_IOCTL
    mov ebx, _TELETYPE_CURRENT
    mov ecx, TCSETSF
    int 030H
    ret

_shell_set_cook_mode:
    xor eax, eax
    mov al, _SYSCALL_IOCTL
    mov ebx, _TELETYPE_CURRENT
    mov ecx, TCGETS
    lea edx, [esp-_termios.sizeof]
    int 030H
    or dword [edx+_termios.oflag], OPOST
    or dword [edx+_termios.iflag], (ICRNL or ISTRIP or IXON)
    or dword [edx+_termios.lflag], (ECHO or ICANON or IEXTEN or ISIG)
    xor eax, eax
    mov al, _SYSCALL_IOCTL
    mov ebx, _TELETYPE_CURRENT
    mov ecx, TCSETSF
    int 030H
    ret

_shell_prompt:
    xor eax, eax
    mov al, _SYSCALL_GUID
    int 030H
    cmp eax, _ROOT_UID
    jz _shell_prompt_root
    mov ecx, _shell_user
    mov edx, _shell_user.sizeof
    jmp _shell_prompt_display
_shell_prompt_root:
    mov ecx, _shell_root
    mov edx, _shell_root.sizeof
_shell_prompt_display:
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    int 030H
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _shell_space
    mov edx, _shell_space.sizeof
    int 030H
    ret
    
_shell_command_shift:
    jecxz _shell_command_shift_exit
    rep movsb
_shell_command_shift_exit:
    cld
    ret

_shell_command_remove:
    mov ecx, dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.cursor]
    jecxz _shell_command_remove_exit
    lea edi, [_SHELL_BUFFER_INTERNAL+_shell_aggregate.command.buffer+ecx-1H]
    lea esi, [edi+1H]
    mov edx, dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.command.length]
    mov ebx, edx
    xchg edx, ecx
    sub ecx, edx
    push ebx edi ecx
    call _shell_command_shift
    call _shell_cursor_backward
    mov ebx, dword [esp+8H]
    mov byte [_SHELL_BUFFER_INTERNAL+_shell_aggregate.command.buffer+ebx-1H], 020H
    call _shell_hide_save_cursor
    pop ecx edi
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    lea edx, [ecx+1H]
    mov ecx, edi
    int 030H
    call _shell_restore_show_cursor
    pop ebx
    mov byte [_SHELL_BUFFER_INTERNAL+_shell_aggregate.command.buffer+ebx-1H], 0H
    dec dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.command.length]
_shell_command_remove_exit:
    ret

_shell_command_insert:
 ; in:
 ;  eax - input buffer
 ;  ebx - number of character to insert
 ; preserves: eax, ebp
    push eax ebp
    mov ecx, _USER_COMMAND_SIZE
    mov edx, dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.command.length]
    sub ecx, edx ; remain length in the buffer
    jbe _shell_command_insert_exit
    cmp ebx, ecx
    cmovb ecx, ebx
    test ecx, ecx
    jz _shell_command_insert_exit
    lea esi, [_SHELL_BUFFER_INTERNAL+_shell_aggregate.command.buffer+edx-1H]
    lea edi, [esi+ecx]
    mov ebp, ecx
    mov ecx, dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.cursor]
    sub edx, ecx
    xchg ecx, edx ; size of string to shift
    mov ebx, ecx
    std
    call _shell_command_shift
    mov ecx, ebp
    add dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.cursor], ecx
    add dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.command.length], ecx
    mov esi, eax
    lea edi, [_SHELL_BUFFER_INTERNAL+_shell_aggregate.command.buffer+edx]
    mov edx, edi
    rep movsb
    mov esi, ebx
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ecx, edx
    mov edx, ebp
    mov ebx, _TELETYPE_CURRENT
    int 030H
    test esi, esi
    jz _shell_command_insert_exit
    lea edi, [ecx+ebp]
    call _shell_hide_save_cursor
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ecx, edi
    mov edx, esi
    int 030H
    call _shell_restore_show_cursor
_shell_command_insert_exit:
    pop ebp eax
    ret

_shell_read_one_character:
    xor eax, eax
    mov al, _SYSCALL_READ
    mov ebx, _TELETYPE_CURRENT
    mov ecx, (_SHELL_BUFFER_INTERNAL + _shell_aggregate.insert)
    xor edx, edx
    inc dl
    int 030H
    movzx eax, byte [_SHELL_BUFFER_INTERNAL+_shell_aggregate.insert]
    ret

_shell_cursor_forward:
 ; preserves: esi, edi, ebp
    mov eax, dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.cursor]
    cmp eax, dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.command.length]
    jae _shell_cursor_forward_exit
    inc dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.cursor]
    call _shell_get_winsize
    movzx esi, word [ebx+_winsize.ws_row]
    movzx edi, word [ebx+_winsize.ws_col]
    call _shell_request_cursor_position
    dec edi
    cmp edx, edi
    jnz _shell_cursor_forward_escape    
    mov ebp, edx
    call _shell_hide_cursor
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _move_down
    mov edx, _move_down.sizeof
    int 030H
    call _shell_get_first_column
    jmp _shell_cursor_forward_exit
_shell_cursor_forward_escape:
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _move_right
    mov edx, _move_right.sizeof
    int 030H
_shell_cursor_forward_exit:
    ret

_shell_cursor_backward:
 ; preserves: esi, edi
    mov eax, dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.cursor]
    test eax, eax
    jz _shell_cursor_backward_exit
    dec dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.cursor]
    call _shell_request_cursor_position
    test dx, dx
    jnz _shell_cursor_backward_escape
    xor eax, eax
    call _shell_hide_cursor
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _move_up
    mov edx, _move_up.sizeof
    int 030H
    call _shell_get_winsize
    movzx ebp, word [ebx+_winsize.ws_col]
    dec ebp
    call _shell_get_last_column
    jmp _shell_cursor_backward_exit
_shell_cursor_backward_escape:
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _move_left
    mov edx, _move_left.sizeof
    int 030H
_shell_cursor_backward_exit:
    ret

_shell_allocate_struct:
    xor eax, eax
    mov al, _SYSCALL_AMAP
    mov ebx, _SHELL_BUFFER_INTERNAL
    mov ecx, _shell_aggregate.sizeof
    mov edx, (_PROT_READ or _PROT_WRITE)
    mov esi, _AMAP_FIXED
    int 030H
    mov edi, (_SHELL_BUFFER_INTERNAL + _shell_aggregate.hsttlb)
    lea eax, [edi+_SIZE_HISTORY*4H]
    mov ecx, _SIZE_HISTORY
    jecxz _shell_allocate_struct_exit
_shell_allocate_struct_loop:
    stosd
    add eax, _line_instance.sizeof
    loop _shell_allocate_struct_loop
_shell_allocate_struct_exit:
    ret

_shell_request_cursor_position:
 ; out:
 ;  eax - row position
 ;  edx - column position
    push edi ebp
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _position_cursor
    mov edx, _position_cursor.sizeof
    int 030H
_shell_request_cursor_position_loop:
    call _shell_read_one_character
    cmp al, _ESCAPE
    jnz _shell_request_cursor_position_loop
    call _shell_read_one_character
    cmp al, _ESCAPE_CURSOR_RECEIVE
    jnz _shell_request_cursor_position_loop
    xor ebp, ebp
    xor edi, edi
_shell_request_cursor_position_convert:
    call _shell_read_one_character
    cmp edi, 4H
    jz _shell_request_cursor_position_update
    sub al, 030H
    cmp al, 9H
    jbe _shell_request_cursor_position_or
    sub al, 7H
_shell_request_cursor_position_or:
    shl ebp, 4H
    or ebp, eax
_shell_request_cursor_position_update:
    inc edi
    cmp edi, 8H
    jbe _shell_request_cursor_position_convert
    xor eax, eax
    mov al, _SYSCALL_IOCTL
    mov ebx, _TELETYPE_CURRENT
    mov ecx, TCFLSH
    int 030H
    movzx edx, bp
    shr ebp, 010H
    movzx eax, bp
    pop ebp edi
    ret

_shell_get_winsize:
    xor eax, eax
    mov al, _SYSCALL_IOCTL
    mov ebx, _TELETYPE_CURRENT
    mov ecx, TIOCGWINSZ
    mov edx, (_SHELL_BUFFER_INTERNAL + _shell_aggregate.winsize)
    int 030H
    mov ebx, edx
    ret

_shell_get_last_column:
 ; in: ebp - count
    call _shell_cursor_forward_escape
    dec ebp
    jnz _shell_get_last_column
    jmp _shell_show_cursor

_shell_get_first_column:
 ; in: ebp - count
    call _shell_cursor_backward_escape
    dec ebp
    jnz _shell_get_first_column
    jmp _shell_show_cursor

_shell_save_cursor:
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _save_cursor
    mov edx, _save_cursor.sizeof
    int 030H
    ret

_shell_restore_cursor:
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _restore_cursor
    mov edx, _restore_cursor.sizeof
    int 030H
    ret

_shell_hide_cursor:
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _hide_cursor
    mov edx, _hide_cursor.sizeof
    int 030H
    ret

_shell_show_cursor:
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _show_cursor
    mov edx, _show_cursor.sizeof
    int 030H
    ret

_shell_skip_whitespace:
 ; in:
 ;  ecx - buffer length
 ;  edi - buffer
 ; out:
 ;  ecx - updated
 ;  edi - updated
 ;   zf - if no whitespace character has been found
    test ecx, ecx
    jz _shell_skip_whitespace_empty
    mov al, 020H
    repz scasb
    jz _shell_skip_whitespace_empty
    lea edi, [edi-1H]
    lea ecx, [ecx+1H]
_shell_skip_whitespace_empty:
    ret

_shell_word_compare:
 ; in:
 ;  eax - size of the tested string
 ;  ecx - size of the command buffer entered by the user
 ;  edi - command buffer
 ;  esi - tested string
 ; out: cf - set when no match
    push edi ecx
    xor edx, edx
    sub ecx, eax
    jc _shell_word_compare_error
    setz dl
    xchg eax, ecx
    repz cmpsb
    jnz _shell_word_compare_error
    test dl, dl
    jnz _shell_word_compare_match
    cmp byte [edi], 020H
    jnz _shell_word_compare_error
_shell_word_compare_match:
    add esp, 8H
    clc
    mov ecx, eax
    ret
_shell_word_compare_error:
    stc
    pop ecx edi
    ret

_shell_parse_command:
 ; in:
 ;  eax - size of the tested string
 ;  ebx - user program payload
 ;  ecx - size of the command buffer entered by the user
 ;  edi - command buffer
 ;  esi - tested string
 ;  ebp - user program payload size
    call _shell_word_compare
    jc _shell_parse_command_exit
    call _shell_skip_whitespace
    mov dword [_USER_SHELL_ARGUMENT_VIRTUAL], ecx ; the count of character in the argument immediately after the first argument
    mov esi, edi
    mov edi, (_USER_SHELL_ARGUMENT_VIRTUAL + 4H)
    rep movsb
    mov esi, ebx
    mov edx, (_SHELL_BUFFER_INTERNAL + _shell_aggregate.tty)
    xor eax, eax
    mov al, _SYSCALL_IOCTL
    mov ebx, _TELETYPE_CURRENT
    mov ecx, TIOCGTTYID
    int 030H
    mov edx, dword [edx]
    xor eax, eax
    mov al, _SYSCALL_FORK
    int 030H
    test eax, eax
    jz _shell_parse_command_child
    mov ebx, eax
    xor eax, eax
    mov al, _SYSCALL_SPGID
    xor ecx, ecx
    int 030H
    call _shell_take_terminal_control

    push edx
    xor eax, eax
    mov al, _SYSCALL_WAITPID
    mov ebx, _WAIT_ALL
    xor ecx, ecx
    mov ecx, (_SHELL_BUFFER_INTERNAL + _shell_aggregate.wait)
    xor edx, edx
    mov dl, (WEXITED or WSTOPPED)
    int 030H
    pop edx

    push eax
    mov eax, dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.pid]
    call _shell_take_terminal_control
    call _shell_set_raw_mode
    pop ebp

    cmp byte [_SHELL_BUFFER_INTERNAL+_shell_aggregate.wait], _WSTOPPED
    clc
    jnz _shell_parse_command_exit
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _shell_stopped_1
    mov edx, _shell_stopped_1.sizeof
    int 030H

    mov eax, ebp
    call _vdso_itoa

    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov edx, ecx
    mov ecx, ebx
    mov ebx, _TELETYPE_CURRENT
    int 030H

    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _shell_stopped_2
    mov edx, _shell_stopped_2.sizeof
    int 030H

    call _shell_print_newline
    jmp _shell_parse_command_exit
_shell_parse_command_child:
    xor eax, eax
    mov al, _SYSCALL_GPID
    int 030H
    mov edi, eax
    push 0H
    mov edx, esp
_shell_parse_command_child_again:
    xor eax, eax
    mov al, _SYSCALL_IOCTL
    mov ebx, _TELETYPE_CURRENT
    mov ecx, TIOCGPGRP
    int 030H
    cmp dword [edx], edi
    jnz _shell_parse_command_child_again
    add esp, 4H
    call _shell_set_cook_mode
    xor eax, eax
    mov al, _SYSCALL_EXEC
    mov ebx, esi
    mov ecx, ebp
    int 030H 
_shell_parse_command_child_exit:
    xor eax, eax
    mov al, _SYSCALL_EXIT
    int 030H
_shell_parse_command_exit:
    ret

_shell_take_terminal_control:
 ; in:
 ;  eax - fg id
 ;  edx - tty id
 ; out: cf - set on error
    push eax edx
    xor eax, eax
    mov al, _SYSCALL_IOCTL
    mov ebx, dword [esp]
    mov ecx, TIOCSPGRP
    lea edx, [esp+4H]
    int 030H
    test eax, eax
    jns _shell_take_terminal_control_exit
    stc
_shell_take_terminal_control_exit:
    pop edx eax
    ret

_shell_copy_line_instance:
    mov ecx, (_line_instance.sizeof shr 2H)
    rep movsd
    ret

_shell_clear_line_instance:
    mov ecx, (_line_instance.sizeof shr 2H)
    xor eax, eax
    rep stosd
    ret

_shell_backup_command_to_history:
    mov edi, eax
    mov esi, (_SHELL_BUFFER_INTERNAL + _shell_aggregate.command)
    jmp _shell_copy_line_instance

_shell_save_indexed_history:
    mov eax, dword [(_SHELL_BUFFER_INTERNAL+_shell_aggregate.hsttlb)+eax*4H]
    jmp _shell_backup_command_to_history

_shell_save_history:
if (_SIZE_HISTORY)
    cmp byte [_SHELL_BUFFER_INTERNAL+_shell_aggregate.hstste], 0H
    jz _shell_save_history_exit
    xor ebx, ebx
    movzx eax, byte [_SHELL_BUFFER_INTERNAL+_shell_aggregate.hstcnt]
    cmp eax, _SIZE_HISTORY
    jb _shell_save_history_update
    inc bl
    mov edi, (_SHELL_BUFFER_INTERNAL + _shell_aggregate.hsttlb)
    mov edx, dword [edi]
    lea esi, [edi+4H]
    mov ecx, (_SIZE_HISTORY - 1H)
    mov eax, ecx
    rep movsd
    mov dword [edi], edx
_shell_save_history_update:
    call _shell_save_indexed_history
    test bl, bl
    jnz _shell_save_history_exit
    inc byte [_SHELL_BUFFER_INTERNAL+_shell_aggregate.hstcnt]
_shell_save_history_exit:
    mov al, byte [_SHELL_BUFFER_INTERNAL+_shell_aggregate.hstcnt]
    mov byte [_SHELL_BUFFER_INTERNAL+_shell_aggregate.hstidx], al
end if
    ret

_shell_import_command_from_history:
    push eax
    call _shell_begin_cursor
    pop eax
    mov edi, (_SHELL_BUFFER_INTERNAL + _shell_aggregate.command)
    mov esi, eax
    call _shell_copy_line_instance
    call _shell_hide_save_cursor
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, (_SHELL_BUFFER_INTERNAL + _shell_aggregate.command.buffer)
    mov edx, [_SHELL_BUFFER_INTERNAL+_shell_aggregate.command.length]
    int 030H
    call _shell_restore_show_cursor
    jmp _shell_end_cursor

_shell_move_up_history:
    cmp byte [_SHELL_BUFFER_INTERNAL+_shell_aggregate.hstste], 0H
    jz _shell_move_up_history_exit
    movzx ecx, byte [_SHELL_BUFFER_INTERNAL+_shell_aggregate.hstidx]
    jecxz _shell_move_up_history_exit
    push ecx
    cmp cl, byte [_SHELL_BUFFER_INTERNAL+_shell_aggregate.hstcnt]
    jnz _shell_move_up_history_refresh
    mov eax, (_SHELL_BUFFER_INTERNAL + _shell_aggregate.temporary)
    call _shell_backup_command_to_history
    jmp _shell_move_up_history_erase
_shell_move_up_history_refresh:
    mov eax, dword [esp]
    call _shell_save_indexed_history
_shell_move_up_history_erase:
    call _shell_erase_whole_line
    pop eax
    mov eax, dword [(_SHELL_BUFFER_INTERNAL+_shell_aggregate.hsttlb-4H)+eax*4H]
    call _shell_import_command_from_history
    dec byte [_SHELL_BUFFER_INTERNAL+_shell_aggregate.hstidx]
_shell_move_up_history_exit:
    ret

_shell_move_down_history:
    cmp byte [_SHELL_BUFFER_INTERNAL+_shell_aggregate.hstste], 0H
    jz _shell_move_down_history_exit
    mov cl, byte [_SHELL_BUFFER_INTERNAL+_shell_aggregate.hstidx]
    mov dl, byte [_SHELL_BUFFER_INTERNAL+_shell_aggregate.hstcnt]
    cmp cl, dl
    jae _shell_move_down_history_exit
    pushw cx dx
    movzx eax, byte [esp+2H]
    call _shell_save_indexed_history
    call _shell_erase_whole_line
    popw dx cx
    inc cl
    cmp cl, dl
    jz _shell_move_down_history_temporary
    movzx eax, cl
    mov eax, dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.hsttlb+eax*4H]
    jmp _shell_move_down_history_import
_shell_move_down_history_temporary:
    mov eax, (_SHELL_BUFFER_INTERNAL + _shell_aggregate.temporary)
_shell_move_down_history_import:
    call _shell_import_command_from_history
    inc byte [_SHELL_BUFFER_INTERNAL+_shell_aggregate.hstidx]
_shell_move_down_history_exit:
    ret

_shell_begin_cursor:
    mov ecx, dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.cursor]
    jecxz _shell_begin_cursor_exit
_shell_begin_cursor_loop:
    push ecx
    call _shell_cursor_backward
    pop ecx
    dec ecx
    jnz _shell_begin_cursor_loop
_shell_begin_cursor_exit:
    ret

_shell_end_cursor:
    mov ecx, dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.command.length]
    sub ecx, dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.cursor]
    jz _shell_end_cursor_exit
_shell_end_cursor_loop:
    push ecx
    call _shell_cursor_forward
    pop ecx
    dec ecx
    jnz _shell_end_cursor_loop
_shell_end_cursor_exit:
    ret

_shell_truncate:
    mov ecx, dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.command.length]
    mov ebx, dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.cursor]
    sub ecx, ebx
    jz _shell_truncate_exit
    lea edi, [_SHELL_BUFFER_INTERNAL+_shell_aggregate.command.buffer+ebx]
    push ebx edi ecx
    mov al, 020H
    rep stosb
    call _shell_hide_save_cursor
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, dword [esp+4H]
    mov edx, dword [esp]
    int 030H
    call _shell_restore_show_cursor
    pop ecx edi
    xor al, al
    rep stosb
    pop dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.command.length]
_shell_truncate_exit:
    ret

_shell_erase_whole_line:
    call _shell_begin_cursor
    jmp _shell_truncate

_shell_command_unknown:
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _shell_invalid
    mov edx, _shell_invalid.sizeof
    int 030H
    ret

_shell_enable_history:
    mov byte [_SHELL_BUFFER_INTERNAL+_shell_aggregate.hstste], (not 0H)
    ret
    
_shell_disable_history:
    mov byte [_SHELL_BUFFER_INTERNAL+_shell_aggregate.hstste], 0H
    jmp _shell_clear_history

_shell_clear_history:
    mov byte [_SHELL_BUFFER_INTERNAL+_shell_aggregate.hstcnt], 0H
    mov byte [_SHELL_BUFFER_INTERNAL+_shell_aggregate.hstidx], 0H
    ret

_shell_ensure_no_params:
    call _shell_skip_whitespace
    jz _shell_ensure_no_params_exit
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _shell_bad_params
    mov edx, _shell_bad_params.sizeof
    int 030H
    stc
    jmp $+3H
_shell_ensure_no_params_exit:
    clc
    ret

_shell_exit_command:
    call _shell_ensure_no_params
    jc _shell_exit_command_exit
    xor eax, eax
    mov al, _SYSCALL_EXIT
    xor ebx, ebx
    int 030H
_shell_exit_command_exit:
    ret

_shell_history_command:
    call _shell_skip_whitespace
    jz _shell_history_command_error
 irp _kind*, on,off
 {
    mov eax, _shell_history_#_kind#.sizeof
    mov esi, _shell_history_#_kind
    call _shell_word_compare
    match =on, _kind \{ jnc _shell_history_command_on \}
    match =off, _kind \{ jnc _shell_history_command_off \}
 }
    jmp _shell_history_command_error
_shell_history_command_on:
    call _shell_ensure_no_params
    jc _shell_history_command_exit
    call _shell_enable_history
    jmp _shell_history_command_exit
_shell_history_command_off:
    call _shell_ensure_no_params
    jc _shell_history_command_exit
    call _shell_disable_history
    jmp _shell_history_command_exit
_shell_history_command_error:
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _shell_history_invalid
    mov edx, _shell_history_invalid.sizeof
    int 030H
_shell_history_command_exit:
    ret

_shell_parse_string:
    push edi ecx
    cmp ecx, 2H
    jb _shell_parse_string_carry
    mov esi, edi
    dec ecx
    lodsb
    call _shell_parse_string_delim
    jnz _shell_parse_string_carry
    mov dl, al
    mov edi, (_SHELL_BUFFER_INTERNAL + _shell_aggregate.temporary.buffer)
    mov ebx, ecx
_shell_parse_string_loop:
    lodsb
    cmp al, dl
    jnz _shell_parse_string_store
    dec ecx     
    jecxz _shell_parse_string_save
    lodsb
    cmp al, dl
    jnz _shell_parse_string_adjust_pointer
    dec ebx
_shell_parse_string_store:
    stosb
    loop _shell_parse_string_loop
    jmp _shell_parse_string_carry
_shell_parse_string_adjust_pointer:
    dec esi
_shell_parse_string_save:
    sub ebx, ecx
    dec ebx
    mov dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.temporary.length], ebx
    mov edi, esi
    add esp, 8H
    clc
    jmp _shell_parse_string_exit
_shell_parse_string_carry:
    pop ecx edi
    stc
_shell_parse_string_exit:
    ret

_shell_parse_string_delim:
    cmp al, 022H
    jz _shell_parse_string_delim_exit
    cmp al, 027H
_shell_parse_string_delim_exit:
    ret

_shell_copy_command:
    call _shell_skip_whitespace
    jz _shell_copy_command_error
    call _shell_parse_string
    jc _shell_copy_command_word
_shell_copy_command_sanitize:
    call _shell_ensure_no_params
    jc _shell_copy_command_exit
    mov edi, (_SHELL_BUFFER_INTERNAL + _shell_aggregate.copy)
    mov esi, (_SHELL_BUFFER_INTERNAL + _shell_aggregate.temporary)
    call _shell_copy_line_instance
    jmp _shell_copy_command_exit
_shell_copy_command_word:
    mov esi, edi
    mov al, 020H
    repnz scasb
    jnz _shell_copy_command_extract
    dec edi
    inc ecx
_shell_copy_command_extract:
    push edi ecx
    mov ecx, edi
    sub ecx, esi
    mov dword [_SHELL_BUFFER_INTERNAL+_shell_aggregate.temporary.length], ecx
    mov edi, (_SHELL_BUFFER_INTERNAL + _shell_aggregate.temporary.buffer)
    rep movsb
    pop ecx edi
    jmp _shell_copy_command_sanitize
_shell_copy_command_error:
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _shell_copy_invalid
    mov edx, _shell_copy_invalid.sizeof
    int 030H
    call _shell_print_newline
_shell_copy_command_exit:
    ret

_shell_print_newline:
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _shell_newline
    mov edx, _shell_newline.sizeof
    int 030H
    ret

_shell_hide_save_cursor:
    call _shell_hide_cursor
    jmp _shell_save_cursor

_shell_restore_show_cursor:
    call _shell_restore_cursor
    jmp _shell_show_cursor

_shell_sighup:
    ret

_shell_sigint_handler:
    ret

_shell_root string "#"
_shell_user string "$"
_shell_space string " "
_shell_newline string 00DH, 00AH

_shell_help string "help"
_shell_copyright string "copyright"
_shell_uid string "uid"
_shell_kill string "kill"
_shell_hostname string "hostname"
_shell_uname string "uname"
_shell_shutdown string "shutdown"
_shell_reboot string "reboot"
_shell_fg string "fg"
_shell_bg string "bg"
_shell_resolution string "resolution"
_shell_clear string "clear"

_shell_copy string "copy"
_shell_copy_invalid string "copy syntax error"

_shell_exit string "exit"
_shell_exit_invalid string "exit error", 00DH, 00AH
_shell_history string "history"
_shell_history_on string "on"
_shell_history_off string "off"
_shell_history_invalid string "history syntax error", 00DH, 00AH

_shell_invalid string "invalid command", 00DH, 00AH

_shell_bad_params string "bad parameter", 00DH, 00AH

_shell_sigint string "sigint"
_shell_usertest string "usertest"
_shell_segvtest string "segvtest"

_shell_sqrt string "sqrt"
_shell_sockpoc string "sockpoc"
_shell_md5 string "md5"

_shell_bomb string "bomb"

_shell_invopcode string "invopcode"

_shell_showpid string "showpid"

_shell_print string "print"

_shell_stopped_1 string "process stopped [PID "
_shell_stopped_2 string "]"

_move_up string _ESCAPE, _ESCAPE_MOVE_UP
_move_down string _ESCAPE, _ESCAPE_MOVE_DOWN
_move_left string _ESCAPE, _ESCAPE_MOVE_LEFT
_move_right string _ESCAPE, _ESCAPE_MOVE_RIGHT

_save_cursor string _ESCAPE, _ESCAPE_SAVE_CURSOR
_restore_cursor string _ESCAPE, _ESCAPE_RESTORE_CURSOR

_hide_cursor string _ESCAPE, _ESCAPE_DISABLE_CURSOR
_show_cursor string _ESCAPE, _ESCAPE_ENABLE_CURSOR

_position_cursor string _ESCAPE, _ESCAPE_CURSOR_POSITION

_extract _help
_extract _copyright
_extract _uid
_extract _kill
_extract _uname
_extract _hostname
_extract _shutdown
_extract _bomb
_extract _reboot
_extract _fg
_extract _bg
_extract _resolution
_extract _clear
_extract _sigint
_extract _usertest
_extract _segvtest
_extract _sockpoc
_extract _sqrt
_extract _md5
_extract _invopcode
_extract _showpid
_extract _print

_shell.sizeof = ($ - $$)
end virtual



struct _color_field _string*, _length*, _escape*, _categorie*, _payload*
    .string:            dd (_string)
    .length:            dd (_length)
    .escape:            db (_escape)
    .categorie:         db (_categorie)
    .payload:           dw (_payload)
ends

irp _kind*, fg,bg
{
    virtual at _USER_CODE_VIRTUAL
    _#_kind::
        xor eax, eax
        mov al, _SYSCALL_ARGCPY
        int 030H
        mov edx, dword [_USER_SHELL_ARGUMENT_VIRTUAL]
        test edx, edx
        jnz _#_kind#_start
    _#_kind#_error:
        xor eax, eax
        mov al, _SYSCALL_WRITE
        mov ebx, _TELETYPE_CURRENT
        mov ecx, _#_kind#_invalid
        mov edx, _#_kind#_invalid.sizeof
        int 030H
        mov ebx, (not 0H)
        jmp _#_kind#_exit
    _#_kind#_start:
        mov ebp, ((_#_kind#_color_table_end - _#_kind#_color_table) / _color_field.sizeof)
        mov ebx, _#_kind#_color_table
    _#_kind#_loop:
        mov edi, (_USER_SHELL_ARGUMENT_VIRTUAL + 4H)
        mov esi, dword [ebx+_color_field.string]
        mov ecx, dword [ebx+_color_field.length]
        jecxz _#_kind#_loop_update
        cmp ecx, edx
        ja _#_kind#_loop_update
        rep cmpsb
        jz _#_kind#_loop_continue
    _#_kind#_loop_update:
        add ebx, _color_field.sizeof
        dec ebp
        jnz _#_kind#_loop
        jmp _#_kind#_error
    _#_kind#_loop_continue:
        sub edx, dword [ebx+_color_field.length]
        jz _#_kind#_loop_display
        mov ecx, edx
        mov al, 020H
        repz scasb
        jnz _#_kind#_error
    _#_kind#_loop_display:
        xor eax, eax
        mov al, _SYSCALL_WRITE
        lea ecx, [ebx+_color_field.escape]
        xor edx, edx
        mov dl, 4H
        mov ebx, _TELETYPE_CURRENT
        int 030H
        xor ebx, ebx
    _#_kind#_exit:
        xor eax, eax
        mov al, _SYSCALL_EXIT
        int 030H

    _#_kind#_color_string_0 string "black"
    _#_kind#_color_string_1 string "blue"
    _#_kind#_color_string_2 string "green"
    _#_kind#_color_string_3 string "cyan"
    _#_kind#_color_string_4 string "red"
    _#_kind#_color_string_5 string "magenta"
    _#_kind#_color_string_6 string "brown"
    _#_kind#_color_string_7 string "light"

    match =fg, _kind \{ define _categorie _ESCAPE_CHANGE_FOREGROUND \}
    match =bg, _kind \{ define _categorie _ESCAPE_CHANGE_BACKGROUND \}

    _#_kind#_color_table:
        _#_kind#_color_0 _color_field _#_kind#_color_string_0, _#_kind#_color_string_0.sizeof, _ESCAPE, _categorie, "00"
        _#_kind#_color_1 _color_field _#_kind#_color_string_1, _#_kind#_color_string_1.sizeof, _ESCAPE, _categorie, "01"
        _#_kind#_color_2 _color_field _#_kind#_color_string_2, _#_kind#_color_string_2.sizeof, _ESCAPE, _categorie, "02"
        _#_kind#_color_3 _color_field _#_kind#_color_string_3, _#_kind#_color_string_3.sizeof, _ESCAPE, _categorie, "03"
        _#_kind#_color_4 _color_field _#_kind#_color_string_4, _#_kind#_color_string_4.sizeof, _ESCAPE, _categorie, "04"
        _#_kind#_color_5 _color_field _#_kind#_color_string_5, _#_kind#_color_string_5.sizeof, _ESCAPE, _categorie, "05"
        _#_kind#_color_6 _color_field _#_kind#_color_string_6, _#_kind#_color_string_6.sizeof, _ESCAPE, _categorie, "06"
        _#_kind#_color_7 _color_field _#_kind#_color_string_7, _#_kind#_color_string_7.sizeof, _ESCAPE, _categorie, "07"
    _#_kind#_color_table_end:

    _#_kind#_invalid string `_kind, " invalid usage", 00AH
    _#_kind#.sizeof = ($ - $$)
    end virtual
}

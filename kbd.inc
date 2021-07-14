
_KEYBOARD_CONTROL                   = 064H
_KEYBOARD_ENCODER                   = 060H
_KEYBOARD_CONTROL_STATUS_OUT        = 1B
_KEYBOARD_CONTROL_STATUS_IN         = 010B
_KEYBOARD_CONTROL_READ_COMMAND      = 020H
_KEYBOARD_CONTROL_ENABLE_KEYBOARD   = 0AEH   
_KEYBOARD_ENCODER_SET_LED           = 0EDH
_KEYBOARD_ENCODER_SET_SCAN_CODE     = 0F0H
_KEYBOARD_ENCODER_ENABLE_KEYBOARD   = 0F4H
_XT_SCAN_CODE                       = 2H
_XT_BREAK_CODE                      = 080H
_EXTENDED_1_CODE                    = 0E0H
_EXTENDED_2_CODE                    = 0E1H
_ESCAPE                             = 01BH

enum    _KEY_NULL, _KEY_ESC, _KEY_1, _KEY_2, _KEY_3, _KEY_4, _KEY_5, _KEY_6, _KEY_7, _KEY_8, _KEY_9, _KEY_0,\
        _KEY_MINUS, _KEY_EQUAL, _KEY_BACKSPACE, _KEY_TAB, _KEY_Q, _KEY_W, _KEY_E, _KEY_R, _KEY_T, _KEY_Y,\
        _KEY_U, _KEY_I, _KEY_O, _KEY_P, _KEY_LEFT_BRACK, _KEY_RIGHT_BRACK, _KEY_ENTER, _KEY_KEYPAD_ENTER:&,\
        _KEY_LEFT_CTRL, _KEY_RIGHT_CTRL:&, _KEY_PAUSE_1:&, _KEY_A, _KEY_S, _KEY_D, _KEY_F, _KEY_G, _KEY_H, _KEY_J,\
        _KEY_K, _KEY_L, _KEY_SEMICOLON, _KEY_QUOTE, _KEY_BACK_TICK, _KEY_LEFT_SHIFT, _KEY_PRINT_SCREEN_1:&, _KEY_BACKSLASH,\
        _KEY_Z, _KEY_X, _KEY_C, _KEY_V, _KEY_B, _KEY_N, _KEY_M, _KEY_COMMA, _KEY_DOT, _KEY_SLASH, _KEY_KEYPAD_SLASH:&,\
        _KEY_RIGHT_SHIFT, _KEY_KEYPAD_STAR, _KEY_PRINT_SCREEN_2:&, _KEY_LEFT_ALT, _KEY_RIGHT_ALT:&, _KEY_SPACE,\
        _KEY_CAPS_LOCK, _KEY_F1, _KEY_F2, _KEY_F3, _KEY_F4, _KEY_F5, _KEY_F6, _KEY_F7, _KEY_F8, _KEY_F9, _KEY_F10,\
        _KEY_KEYPAD_NUM_LOCK, _KEY_PAUSE_2:&, _KEY_SCROLL_LOCK, _KEY_HOME, _KEY_KEYPAD_7:&, _KEY_UP_ARROW, _KEY_KEYPAD_8:&,\
        _KEY_PAGE_UP, _KEY_KEYPAD_9:&, _KEY_KEYPAD_MINUS, _KEY_LEFT_ARROW, _KEY_KEYPAD_4:&, _KEY_KEYPAD_5, _KEY_RIGHT_ARROW,\
        _KEY_KEYPAD_6:&, _KEY_KEYPAD_PLUS, _KEY_END, _KEY_KEYPAD_1:&, _KEY_DOWN_ARROW, _KEY_KEYPAD_2:&, _KEY_PAGE_DOWN,\
        _KEY_KEYPAD_3:&, _KEY_INSERT, _KEY_KEYPAD_0:&, _KEY_DELETE, _KEY_KEYPAD_DOT:&, _KEY_F11:057H, _KEY_F12,\
        _KEY_LEFT_GUI:05BH, _KEY_RIGHT_GUI, _KEY_APPS, _KEY_PRINT_SCREEN, _KEY_PAUSE

enum    _ESC_ESC:080H, _ESC_LEFT_ARROW, _ESC_RIGHT_ARROW, _ESC_UP_ARROW, _ESC_DOWN_ARROW, _ESC_F1, _ESC_F2,\
        _ESC_F3, _ESC_F4, _ESC_F5, _ESC_F6, _ESC_F7, _ESC_F8, _ESC_F9, _ESC_F10, _ESC_F11, _ESC_F12,\
        _ESC_PAGE_UP, _ESC_PAGE_DOWN, _ESC_HOME, _ESC_END, _ESC_INSERT, _ESC_DELETE

_keyboard_control_wait_output_full:
    in al, _KEYBOARD_CONTROL
    test al, _KEYBOARD_CONTROL_STATUS_OUT
    jz _keyboard_control_wait_output_full
    ret

_keyboard_control_wait_input_empty:
    in al, _KEYBOARD_CONTROL
    test al, _KEYBOARD_CONTROL_STATUS_IN
    jnz _keyboard_control_wait_input_empty
    ret

enum & _KEY_MAKE_CODE, _KEY_NOTIFY
_keyboard_driver:
 ; out:
 ;  eax - ascii character in al and scan code in ah (except for _ESCAPE)
 ;   cf - set if the key pressed was not a notifiable key
 ; note: al = _KEY_NULL when no "printable" character has been entered
 ; preserves: esi, edi, ebp
    call _keyboard_control_wait_output_full
    xor eax, eax
    xor ecx, ecx
    in al, _KEYBOARD_ENCODER
    xchg al, ah
    mov dl, _KEY_MAKE_CODE
    cmp ah, _EXTENDED_1_CODE
    jz _keyboard_driver_extended
    cmp ah, _EXTENDED_2_CODE
    jz _keyboard_driver_extended
    test ah, _XT_BREAK_CODE
    jz _keyboard_driver_extended_action
    xor dl, dl
    xor ah, _XT_BREAK_CODE
_keyboard_driver_extended_action:
    mov bl, byte [_current_keyboard.extended]
    test dl, _KEY_MAKE_CODE
    jnz _keyboard_driver_extended_perform
    mov byte [_current_keyboard.extended], _KEY_NULL
_keyboard_driver_extended_perform:
    cmp bl, _EXTENDED_1_CODE
    jz _keyboard_driver_handle_extended_1
    cmp bl, _EXTENDED_2_CODE
    jz _keyboard_driver_handle_extended_2
    jmp _keyboard_driver_make_code
_keyboard_driver_extended:
    mov byte [_current_keyboard.extended], ah
    jmp _keyboard_driver_exit
_keyboard_driver_handle_extended_1:
    cmp ah, _KEY_RIGHT_CTRL
    mov ebx, _current_keyboard.right_ctrl
    jz _keyboard_driver_insert_state
    cmp ah, _KEY_RIGHT_ALT
    mov ebx, _current_keyboard.right_alt
    jz _keyboard_driver_insert_state
    test dl, dl
    jz _keyboard_driver_exit
    cmp ah, _KEY_PRINT_SCREEN_1
    jz _keyboard_driver_exit
    or dl, _KEY_NOTIFY
    cmp ah, _KEY_PRINT_SCREEN_2
    jnz _keyboard_driver_handle_extended_1_numlock
    mov ah, _KEY_PRINT_SCREEN
    jmp _keyboard_driver_exit
_keyboard_driver_handle_extended_1_numlock:
    cmp ah, _KEY_KEYPAD_SLASH
    jz _keyboard_driver_only_numlock
    cmp ah, _KEY_KEYPAD_ENTER
    jz _keyboard_driver_only_numlock
    mov cl, _ESCAPE
 irp _kind*, LEFT_ARROW,RIGHT_ARROW,UP_ARROW,DOWN_ARROW,INSERT,HOME,END,PAGE_UP,PAGE_DOWN
 {
    cmp ah, _KEY_#_kind
    mov ch, _ESC_#_kind
    cmovz eax, ecx
    if (((_KEY_#_kind) = _KEY_LEFT_ARROW) | ((_KEY_#_kind) = _KEY_RIGHT_ARROW) |\
            ((_KEY_#_kind) = _KEY_UP_ARROW) | ((_KEY_#_kind) = _KEY_DOWN_ARROW))
        jz _keyboard_driver_handle_extended_1_arrow
    else
        jz _keyboard_driver_exit
    end if
 }
    xor al, al
    jmp _keyboard_driver_exit
_keyboard_driver_handle_extended_1_arrow:
    call _keyboard_driver_scroll_activated
    jc _keyboard_driver_exit
 irp _kind*, LEFT_ARROW,RIGHT_ARROW,UP_ARROW,DOWN_ARROW
 {
    cmp ah, _ESC_#_kind
    match =LEFT_ARROW, _kind \{ mov ch, _ESC_HOME \}
    match =RIGHT_ARROW, _kind \{ mov ch, _ESC_END \}
    match =UP_ARROW, _kind \{ mov ch, _ESC_PAGE_UP \}
    match =DOWN_ARROW, _kind \{ mov ch, _ESC_PAGE_DOWN \}
    cmovz eax, ecx
    jz _keyboard_driver_exit
 }
_keyboard_driver_handle_extended_2:
    cmp ah, _KEY_PAUSE_2
    jnz _keyboard_driver_exit
    or dl, _KEY_NOTIFY
    mov ah, _KEY_PAUSE
    jmp _keyboard_driver_exit
_keyboard_driver_make_code:
    cmp ah, _KEY_LEFT_CTRL
    mov ebx, _current_keyboard.left_ctrl
    jz _keyboard_driver_insert_state
    cmp ah, _KEY_LEFT_SHIFT
    mov ebx, _current_keyboard.left_shift
    jz _keyboard_driver_insert_state
    cmp ah, _KEY_RIGHT_SHIFT
    mov ebx, _current_keyboard.right_shift
    jz _keyboard_driver_insert_state
    cmp ah, _KEY_LEFT_ALT
    mov ebx, _current_keyboard.left_alt
    jz _keyboard_driver_insert_state
    test dl, dl
    jz _keyboard_driver_exit
    cmp ah, _KEY_CAPS_LOCK
    mov ebx, _current_keyboard.caps_lock
    jz _keyboard_driver_invert_state
    cmp ah, _KEY_KEYPAD_NUM_LOCK
    mov ebx, _current_keyboard.num_lock
    jz _keyboard_driver_invert_state 
    cmp ah, _KEY_SCROLL_LOCK
    mov ebx, _current_keyboard.scroll_lock
    jz _keyboard_driver_invert_state
    or dl, _KEY_NOTIFY
    mov cl, _ESCAPE
 irp _kind*, ESC,F1,F2,F3,F4,F5,F6,F7,F8,F9,F10,F11,F12
 {
    cmp ah, _KEY_#_kind
    mov ch, _ESC_#_kind
    cmovz eax, ecx  
    jz _keyboard_driver_exit
 }
_keyboard_driver_keypad:
 irp _kind*, 0,1,2,3,4,5,6,7,8,9,DOT,MINUS,PLUS,STAR
 {
     cmp ah, _KEY_KEYPAD_#_kind
     jz _keyboard_driver_only_numlock
 }
    jmp _keyboard_driver_translate
_keyboard_driver_only_numlock:
    call _keyboard_driver_num_activated
    jnc _keyboard_driver_translate
    xor dl, _KEY_NOTIFY
    jmp _keyboard_driver_exit
_keyboard_driver_translate:
    mov ebx, _keyboard_translation_table
    mov al, ah
    xlatb
    call _keyboard_driver_shift_pressed
    jc _keyboard_driver_case_update
    mov ch, ah
 irp _kind*, 060H,031H,032H,033H,034H,035H,036H,037H,038H,039H,030H,02DH,03DH,05BH,05DH,05CH,03BH,027H,02CH,02EH,02FH
 {
    cmp al, _kind
    match =060H, _kind \{ mov cl, 07EH \}
    match =031H, _kind \{ mov cl, 021H \}
    match =032H, _kind \{ mov cl, 040H \}
    match =033H, _kind \{ mov cl, 023H \}
    match =034H, _kind \{ mov cl, 024H \}
    match =035H, _kind \{ mov cl, 025H \}
    match =036H, _kind \{ mov cl, 05EH \}
    match =037H, _kind \{ mov cl, 026H \}
    match =038H, _kind \{ mov cl, 02AH \}
    match =039H, _kind \{ mov cl, 028H \}
    match =030H, _kind \{ mov cl, 029H \}
    match =02DH, _kind \{ mov cl, 05FH \}
    match =03DH, _kind \{ mov cl, 02BH \}
    match =05BH, _kind \{ mov cl, 07BH \}
    match =05DH, _kind \{ mov cl, 07DH \}
    match =05CH, _kind \{ mov cl, 07CH \}
    match =03BH, _kind \{ mov cl, 03AH \}
    match =027H, _kind \{ mov cl, 022H \}
    match =02CH, _kind \{ mov cl, 03CH \}
    match =02EH, _kind \{ mov cl, 03EH \}
    match =02FH, _kind \{ mov cl, 03FH \}
    cmovz eax, ecx
    jz _keyboard_driver_transform
 }
    jmp _keyboard_driver_case_convert
_keyboard_driver_case_update:
    call _keyboard_driver_caps_activated
    jc _keyboard_driver_transform
_keyboard_driver_case_convert:
    cmp al, 061H
    jc _keyboard_driver_transform
    cmp al, 07AH
    ja _keyboard_driver_transform
    and al, (not 020H)
_keyboard_driver_transform:
    call _keyboard_driver_ctrl_pressed
    jc _keyboard_driver_exit
    call _keyboard_driver_control_character
_keyboard_driver_exit:
    test dl, _KEY_NOTIFY
    jmp _convert_zero_carry

_keyboard_driver_insert_state:
 ; in: 
 ;  ebx - state in keyboard to change 
 ;   dl - make code or break code
    mov byte [ebx], dl
    and byte [ebx], (not _KEY_NOTIFY)
    jmp _keyboard_driver_exit
_keyboard_driver_invert_state:
 ; in: ebx - state in keyboard to change 
 ; note: must be called to invert the state of a lock key
    xor byte [ebx], _KEY_MAKE_CODE
    call _keyboard_driver_update_led
    jmp _keyboard_driver_exit

_keyboard_driver_control_character:
    cmp al, 041H
    jc _keyboard_driver_control_character_reset
    cmp al, 05AH
    ja _keyboard_driver_control_character_upper
    sub al, 040H
    jmp _keyboard_driver_control_character_exit
_keyboard_driver_control_character_upper:
    cmp al, 061H
    jc _keyboard_driver_control_character_reset
    cmp al, 07AH
    ja _keyboard_driver_control_character_reset
    sub al, 060H
    jmp _keyboard_driver_control_character_exit
_keyboard_driver_control_character_reset:
    xor al, al
_keyboard_driver_control_character_exit:
    ret

_keyboard_driver_update_led:
    push eax edx
    call _keyboard_driver_scroll_activated
    setnc al
    call _keyboard_driver_num_activated
    setnc cl
    shl cl, 1H
    call _keyboard_driver_caps_activated
    setnc dl 
    shl dl, 2H
    or dl, cl
    or dl, al
    call _keyboard_control_wait_input_empty
    mov al, _KEYBOARD_ENCODER_SET_LED
    out _KEYBOARD_ENCODER, al
    call _keyboard_control_wait_input_empty
    mov al, dl
    out _KEYBOARD_ENCODER, al
    pop edx eax
    ret

irp _kind*, ctrl,shift,alt
{
    _keyboard_driver_#_kind#_pressed:
     ; out: cf - set if it's not pressed
        test byte [_current_keyboard.left_#_kind], _KEY_MAKE_CODE
        jnz _convert_zero_carry
        test byte [_current_keyboard.right_#_kind], _KEY_MAKE_CODE
        jmp _convert_zero_carry
}

irp _kind*, scroll,num,caps
{
    _keyboard_driver_#_kind#_activated:
     ; out: cf - set if it's not pressed
        test byte [_current_keyboard.#_kind#_lock], _KEY_MAKE_CODE
        jmp _convert_zero_carry
}

_keyboard_translation_table:
    db 000H, 01BH, 031H, 032H
    db 033H, 034H, 035H, 036H
    db 037H, 038H, 039H, 030H
    db 02DH, 03DH, 07FH, 009H
    db 071H, 077H, 065H, 072H
    db 074H, 079H, 075H, 069H
    db 06FH, 070H, 05BH, 05DH
    db 00DH, 000H, 061H, 073H
    db 064H, 066H, 067H, 068H
    db 06AH, 06BH, 06CH, 03BH
    db 027H, 060H, 000H, 05CH
    db 07AH, 078H, 063H, 076H
    db 062H, 06EH, 06DH, 02CH
    db 02EH, 02FH, 000H, 02AH
    db 000H, 020H, 000H, 01BH
    db 01BH, 01BH, 01BH, 01BH
    db 01BH, 01BH, 01BH, 01BH
    db 01BH, 000H, 000H, 037H
    db 038H, 039H, 02DH, 034H
    db 035H, 036H, 02BH, 031H
    db 032H, 033H, 030H, 02EH
    times (0FFH - ($ - _keyboard_translation_table)) db 0H



_USERNAME_MAX = 010H
_PASSWORD_MAX = _MD5_DIGEST

struct _record _username*, _password*, _uid*
    .username   string _username
    times       (_USERNAME_MAX - .username.sizeof) db 0H
    .password   string _password
    times       (_PASSWORD_MAX - .password.sizeof) db 0H
    .uid:       dd (_uid)
ends

_TELETYPE_ID = _USER_STACK_VIRTUAL

_user_code _login
    ;rept 400H { nop }
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _login_clear
    mov edx, _login_clear.sizeof
    int 030H
    mov eax, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _login_newline
    mov edx, 1H
    int 030H
    mov eax, _SYSCALL_UNAME
    lea ebx, [esp-(_UNAME_SIZE+1H)]
    int 030H
    mov word [ebx+eax], 020H
    mov ecx, ebx
    lea edx, [eax+1H]
    mov eax, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    int 030H
    mov eax, _SYSCALL_IOCTL
    mov ebx, _TELETYPE_CURRENT
    mov ecx, TIOCGTTYID
    mov edx, _TELETYPE_ID
    int 030H
    mov eax, dword [edx]
    add al, (030H + 1H)
    lea ebx, [esp-_login_tty.sizeof]
    mov edi, ebx
    mov esi, _login_tty
    mov ecx, _login_tty.sizeof
    rep movsb
    mov byte [ebx+4H], al
    mov eax, _SYSCALL_WRITE
    mov ecx, ebx
    mov ebx, _TELETYPE_CURRENT
    mov edx, _login_tty.sizeof
    int 030H
    mov eax, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _login_newline
    mov edx, 2H
    int 030H
    mov eax, _SYSCALL_AMAP
    xor ebx, ebx
    xor ecx, ecx
    mov cl, 1H
    mov edx, (_PROT_READ or _PROT_WRITE)
    xor esi, esi
    int 030H
    mov ebp, eax
    mov eax, _SYSCALL_GUID
    int 030H
_login_start:
    call _login_termios_restore
    xor al, al
    mov edi, ebp
    mov ecx, _record.sizeof
    rep stosb
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _login_username
    mov edx, _login_username.sizeof
    int 030H
    xor eax, eax
    mov al, _SYSCALL_READ
    mov ebx, _TELETYPE_CURRENT
    lea ecx, [ebp+_record.username]
    xor edx, edx
    mov dl, _USERNAME_MAX
    int 030H
    test eax, eax
    jz $+7H
    mov byte [ecx+eax-1H], 0H
    call _login_tcgets   
    and word [edx+_termios.lflag], (not ECHO)
    call _login_tcsetsf
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _login_password
    mov edx, _login_password.sizeof
    int 030H
    xor eax, eax
    mov al, _SYSCALL_READ
    mov ebx, _TELETYPE_CURRENT
    lea ecx, [ebp+_record.password]
    xor edx, edx
    mov dl, _PASSWORD_MAX

    mov esi, ebp

    int 030H
    mov esi, eax
    test eax, eax
    jz $+8H
    mov byte [ecx+eax-1H], 0H
    dec esi
    mov ebx, ecx
    mov edx, ecx
    mov ecx, esi
    xor eax, eax
    mov al, _SYSCALL_MD5
    int 030H
    mov ebx, _login_record
    mov edx, ((_login_record_end - _login_record) / _record.sizeof)
_login_loop:
    mov edi, ebx
    mov esi, ebp
    mov ecx, _record.uid
    assert (_record.uid)
    rep cmpsb
    jz _login_found
    dec edx
    jz _login_mismatch
    add ebx, _record.sizeof
    jmp _login_loop
_login_found:
    xor eax, eax
    mov al, _SYSCALL_FORK
    int 030H
    test eax, eax
    jz _login_shell
    mov ebx, eax
    xor eax, eax
    mov al, _SYSCALL_WAITPID
    xor ecx, ecx
    mov edx, WEXITED
    int 030H
    jp _login_start
_login_shell:
    mov esi, ebx
    call _login_termios_restore
    mov eax, _SYSCALL_SSID
    int 030H
    mov dword [esp-4H], eax
    mov eax, _SYSCALL_IOCTL
    mov ebx, dword [_TELETYPE_ID]
    mov ecx, TIOCSCTTY
    int 030H
    xor eax, eax
    mov al, _SYSCALL_IOCTL
    mov ebx, dword [_TELETYPE_ID]
    mov ecx, TIOCSPGRP
    lea edx, [esp-4H]
    int 030H
    mov eax, _SYSCALL_SUID
    mov ebx, dword [esi+_record.uid]
    int 030H
    mov eax, _SYSCALL_EXEC
    mov ebx, _shell_payload
    mov ecx, _shell.sizeof
    int 030H
    mov eax, _SYSCALL_EXIT
    int 030H
_login_mismatch:
    mov eax, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _login_incorrect
    mov edx, _login_incorrect.sizeof
    int 030H
    jmp _login_start

_login_termios_restore:
    call _login_tcgets   
    or dword [edx+_termios.oflag], OPOST
    or word [edx+_termios.iflag], (ICRNL or ISTRIP or IXON)
    or word [edx+_termios.lflag], (ICANON or ECHO or ECHOE or ECHOK or IEXTEN)
    ;or word [edx+_termios.lflag], (TOSTOP)
    and word [edx+_termios.lflag], (not ISIG)
    jmp _login_tcsetsf

_login_tcgets:
 ; out: edx - termios data pointer
    xor eax, eax
    mov al, _SYSCALL_IOCTL
    mov ebx, _TELETYPE_CURRENT
    mov ecx, TCGETS
    lea edx, [esp-_termios.sizeof]
    int 030H
    ret

_login_tcsetsf:
 ; in: edx - termios data pointer
    xor eax, eax
    mov al, _SYSCALL_IOCTL
    mov ebx, _TELETYPE_CURRENT
    mov ecx, TCSETSF
    int 030H
    ret

_login_record:
    _maoko _record "maoko", "E13F65CB8405426C5DF4D661DEEE221E",  _ROOT_UID
    _louis _record "louis", "AEBD920A5BF16E5B4518162A29EA728A",  _ROOT_UID
    _guest _record "guest", "084E0343A0486FF05530DF6C705C8BB4", _GUEST_UID
_login_record_end:

_login_username string "login: "
_login_password string "password: "
_login_incorrect string "login incorrect", 00AH
_login_newline: dw 00A0AH
_login_tty string "(tty_)"
_login_clear string _ESCAPE, _ESCAPE_CLEAR
;align 010H
;_login_aes_key string "AssemblyIsBetter"
;assert (_login_aes_key.sizeof = 010H)
_extract _shell
end _user_code


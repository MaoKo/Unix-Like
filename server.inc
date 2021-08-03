
macro _print_error _string*
{
  xor eax, eax
  mov al, _SYSCALL_WRITE
  mov ebx, _TELETYPE_CURRENT
  mov ecx, _string
  mov edx, _string#.sizeof
  int 030H
}

_SERVER_BUFFER = 0100H
_SERVER_PORT = 050H

virtual at _USER_CODE_VIRTUAL
_server::
    rept 0123H { nop }

    xor eax, eax
    mov al, _SYSCALL_OPEN
    int 030H
    test eax, eax
    js _server_filde_error
    mov ebp, eax
    xor eax, eax
    mov al, _SYSCALL_BIND
    mov ebx, ebp
    xor ecx, ecx
    mov cl, _SERVER_PORT
    int 030H
    test eax, eax
    js _server_bind_error
    lea edi, [esp-_SERVER_BUFFER-1H]
_server_loop:
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _server_listen
    mov edx, _server_listen.sizeof
    int 030H
    xor eax, eax
    mov al, _SYSCALL_LISTEN
    mov ebx, _SERVER_PORT
    int 030H
    xor eax, eax
    mov al, _SYSCALL_RECEIVE
    mov ebx, ebp
    mov ecx, edi
    mov edx, _SERVER_BUFFER
    int 030H
    mov esi, eax

    mov byte [edi+esi], 00AH    
    cmp esi, 4H
    jnz _server_print
    mov edx, dword [edi]
    cmp edx, "QUIT"
    jnz _server_print
    xor ebx, ebx
    jmp _server_exit
_server_print:
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _server_receive
    mov edx, _server_receive.sizeof
    int 030H

    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, edi
    lea edx, [esi+1H]
    int 030H

    jmp _server_loop

_server_filde_error:
    _print_error _server_filde
    jmp _server_error
_server_bind_error:
    _print_error _server_bind
_server_error:
    xor ebx, ebx
    not ebx
_server_exit:
    xor eax, eax
    mov al, _SYSCALL_EXIT
    int 030H

_server_filde string "The server can't open a socket", 00AH
_server_bind string "The server can't bind to port 80", 00AH
_server_listen string "Server listening on port 80 ...", 00AH
_server_receive string "You have received the string : "
_server.sizeof = ($ - $$)
end virtual


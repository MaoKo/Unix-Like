
virtual at _USER_CODE_VIRTUAL
_sockpoc::
    xor eax, eax
    mov al, _SYSCALL_ARGCPY
    int 030H
    cmp dword [_USER_SHELL_ARGUMENT_VIRTUAL], 0H
    jz _sockpoc_start
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _sockpoc_invalid
    mov edx, _sockpoc_invalid.sizeof
    int 030H
    xor ebx, ebx
    not ebx
    jmp _sockpoc_terminate
_sockpoc_start:
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _sockpoc_launch_server
    mov edx, _sockpoc_launch_server.sizeof
    int 030H
    xor eax, eax
    mov al, _SYSCALL_FORK
    int 030H
    test eax, eax
    jnz _sockpoc_launch
    mov al, _SYSCALL_EXEC
    mov ebx, _server_payload
    mov ecx, _server.sizeof
    int 030H
    jmp _sockpoc_terminate-2H
_sockpoc_launch:
    mov dword [_USER_SHELL_ARGUMENT_VIRTUAL], eax
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _sockpoc_launch_client
    mov edx, _sockpoc_launch_client.sizeof
    int 030H
    xor eax, eax
    mov al, _SYSCALL_FORK
    int 030H
    test eax, eax
    jnz _sockpoc_wait
    xor eax, eax
    mov al, _SYSCALL_EXEC
    mov ebx, _client_payload
    mov ecx, _client.sizeof
    int 030H
    jmp _sockpoc_terminate-2H
_sockpoc_wait:
    xor eax, eax
    mov al, _SYSCALL_WAIT
    xor ebx, ebx
    int 030H
    xor ebx, ebx
_sockpoc_terminate:
    xor eax, eax
    mov al, _SYSCALL_EXIT
    int 030H
_extract _client, _server
_sockpoc_invalid string "sockpoc invalid usage", 00AH
_sockpoc_launch_server string "*** Starting the server ***", 00AH
_sockpoc_launch_client string "*** Starting the client ***", 00AH
_sockpoc.sizeof = ($ - $$)
end virtual


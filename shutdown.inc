
virtual at _USER_CODE_VIRTUAL
_shutdown::
    xor eax, eax
    mov al, _SYSCALL_ARGCPY
    int 030H
    cmp dword [_USER_SHELL_ARGUMENT_VIRTUAL], 0H
    jz _shutdown_start
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _shutdown_invalid
    mov edx, _shutdown_invalid.sizeof
    int 030H
    mov ebx, (not 0H)
    jmp _shutdown_exit
_shutdown_start:
    xor eax, eax
    mov al, _SYSCALL_REBOOT
    mov ebx, _REBOOT_MAGIC1
    mov ecx, _REBOOT_MAGIC2
    mov edx, _REBOOT_CMD_HALT
    int 030H
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _shutdown_permission
    mov edx, _shutdown_permission.sizeof
    int 030H
    xor ebx, ebx
_shutdown_exit:
    xor eax, eax
    mov al, _SYSCALL_EXIT
    int 030H
_shutdown_permission string "shutdown permission denied", 00AH
_shutdown_invalid string "shutdown invalid usage", 00AH
_shutdown.sizeof = ($ - $$)
end virtual

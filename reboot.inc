
virtual at _USER_CODE_VIRTUAL
_reboot::
    xor eax, eax
    mov al, _SYSCALL_ARGCPY
    int 030H
    cmp dword [_USER_SHELL_ARGUMENT_VIRTUAL], 0H
    jz _reboot_start
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _reboot_invalid
    mov edx, _reboot_invalid.sizeof
    int 030H
    mov ebx, (not 0H)
    jmp _reboot_exit
_reboot_start:
    xor eax, eax
    mov al, _SYSCALL_REBOOT
    mov ebx, _REBOOT_MAGIC1
    mov ecx, _REBOOT_MAGIC2
    mov edx, _REBOOT_CMD_RESTART
    int 030H
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _reboot_permission
    mov edx, _reboot_permission.sizeof
    int 030H
    xor ebx, ebx
_reboot_exit:
    xor eax, eax
    mov al, _SYSCALL_EXIT
    int 030H
_reboot_permission string "reboot permission denied", 00AH
_reboot_invalid string "reboot invalid usage", 00AH
_reboot.sizeof = ($ - $$)
end virtual

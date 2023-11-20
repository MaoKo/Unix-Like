
_user_code _invopcode
    ud2
    xor eax, eax
    mov al, _SYSCALL_EXIT
    xor ebx, ebx
    int 030H
end _user_code



virtual at _USER_CODE_VIRTUAL
_usertest::
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _usertest_example
    mov edx, _usertest_example.sizeof
    int 030H
    xor eax, eax
    mov al, _SYSCALL_EXIT
    xor ebx, ebx
    int 030H
_usertest_example string "Hello, World!!", 00AH
_usertest.sizeof = ($ - $$)
end virtual


_user_code _usertest
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _usertest_example
    mov edx, _usertest_example.sizeof
    int 030H
_user_test_loop:
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ecx, _usertest_a
    mov edx, _usertest_a.sizeof
    int 030H
    jmp _user_test_loop
    xor eax, eax
    mov al, _SYSCALL_EXIT
    xor ebx, ebx
    int 030H
_usertest_example string "Hello, World!!", 00AH
_usertest_a string "a"
end _user_code

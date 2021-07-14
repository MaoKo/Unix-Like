
virtual at _USER_CODE_VIRTUAL
_sigint::
    xor eax, eax
    mov al, _SYSCALL_SIGNAL
    mov ebx, SIGCONT
    mov ecx, _sigint_sigcont
    int 030H
    xor eax, eax
    mov al, _SYSCALL_SIGNAL
    mov ebx, SIGTTOU
    mov ecx, _sigint_sigttou
    int 030H
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _sigint_info
    mov edx, _sigint_info.sizeof
    int 030H
    jmp $

_sigint_sigcont:
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TTY1
    mov ecx, _sigint_cont
    mov edx, _sigint_cont.sizeof
    int 030H
    ret
 
_sigint_sigttou:
    ret
   
_sigint_info string "you must use CTRL-C to quit this software", 00AH
_sigint_cont string "SIGINT continued", 00AH
_sigint.sizeof = ($ - $$)
end virtual

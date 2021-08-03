
virtual at _USER_CODE_VIRTUAL
_help::
    xor eax, eax
    mov al, _SYSCALL_ARGCPY
    int 030H
    cmp dword [_USER_SHELL_ARGUMENT_VIRTUAL], 0H
    jz _help_start
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _help_invalid
    mov edx, _help_invalid.sizeof
    int 030H
    mov ebx, (not 0H)
    jmp _help_exit
_help_start:
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _help_command
    mov edx, _help_command.sizeof
    int 030H
    xor ebx, ebx
_help_exit:
    xor eax, eax
    mov al, _SYSCALL_EXIT
    int 030H
_help_command string\
    "achiu-au, KFS version 1.0.3", 00AH,\
    "To switch TTY enter CTRL+Fn or left/right window", 00AH,\
    "help               - display help", 00AH,\
    "copyright          - show the copyright", 00AH,\
    "clear              - clear the current screen and the history", 00AH,\
    "fg/bg c            - change foreground/background to c", 00AH,\
    " * [black,blue,green,cyan,red,magenta,brown,light]", 00AH,\
    "copy ""str""         - copy the string to the clipboard", 00AH,\
    " * to include "" in string, double it", 00AH,\
    "usertest           - test new stuff (segfault, undefined opcode ...)", 00AH,\
    "segvtest           - experiment a segmentation fault", 00AH,\
    "sigint             - use sigint to quit the program", 00AH,\
    "sockpoc            - test the server - client idiom", 00AH,\
    "sqrt               - simple routine to compute sqrt", 00AH,\
    "md5 hash           - hash input string to md5", 00AH,\
    "kill signal pid    - send the signal to the process", 00AH,\
    "uid                - show the current uid", 00AH,\
    "uname              - show the version of the OS", 00AH,\
    "hostname           - show the hostname", 00AH,\
    "history on/off     - enable/disable history", 00AH,\
    "resolution x y     - try to change to resolution with the given value", 00AH,\
    "reboot             - reboot the machine", 00AH,\
    "shutdown           - shutdown the machine", 00AH,\
    "exit               - exit the shell", 00AH
_help_invalid string "help invalid usage", 00AH
_help.sizeof = ($ - $$)
end virtual


virtual at _USER_CODE_VIRTUAL
_sqrt::
    xor eax, eax
    mov al, _SYSCALL_ARGCPY
    int 030H
    xor eax, eax
    mov al, _CPUID_LEAF_PROCESSOR_INFO
    cpuid
    test edx, _CPUID_EDX_SSE
    jnz _sqrt_compute
    xor eax, eax
    mov al, _SYSCALL_WRITE
    mov ebx, _TELETYPE_CURRENT
    mov ecx, _sqrt_sse
    mov edx, _sqrt_sse.sizeof
    int 030H
    mov ebx, (not 0H)
    jmp _sqrt_exit
_sqrt_compute:
    xor ebx, ebx
    movd xmm0, eax
    sqrtps xmm0, xmm0
_sqrt_exit:
    xor eax, eax
    mov al, _SYSCALL_EXIT
    int 030H
_sqrt_invalid string "sqrt invalid usage", 00AH
_sqrt_sse string "SSE not supported", 00AH
_sqrt.sizeof = ($ - $$)
end virtual



_user_code _showpid
  xor eax, eax
  mov al, _SYSCALL_WRITE
  mov ebx, _TELETYPE_CURRENT
  mov ecx, _parent_pid
  mov edx, _parent_pid.sizeof
  int 030H
  xor eax, eax
  mov al, _SYSCALL_GPPID
  int 030H
  call _vdso_itoa
  mov edx, ecx
  mov ecx, ebx
  mov ebx, _TELETYPE_CURRENT
  xor eax, eax
  mov al, _SYSCALL_WRITE
  int 030H
  xor eax, eax
  mov al, _SYSCALL_WRITE
  mov ecx, _newline
  xor edx, edx
  inc dl
  int 030H
  xor eax, eax
  mov al, _SYSCALL_WRITE
  mov ecx, _process_pid
  mov edx, _process_pid.sizeof
  int 030H
  xor eax, eax
  mov al, _SYSCALL_GPID
  int 030H
  call _vdso_itoa
  mov edx, ecx
  mov ecx, ebx
  mov ebx, _TELETYPE_CURRENT
  xor eax, eax
  mov al, _SYSCALL_WRITE
  int 030H
  xor eax, eax
  mov al, _SYSCALL_WRITE
  mov ecx, _newline
  xor edx, edx
  inc dl
  int 030H
  xor eax, eax
  mov al, _SYSCALL_EXIT
  int 030H
_process_pid string "Process pid: "
_parent_pid string "Parent pid: "
_newline string 00AH
end _user_code


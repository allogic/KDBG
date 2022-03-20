stack struct
  OrigMxcsr qword ?
  OrigRAX   qword ?       ; 0
  OrigRBX   qword ?       ; 1
  OrigRCX   qword ?       ; 2
  OrigRDX   qword ?       ; 3
  OrigRSI   qword ?       ; 4
  OrigRDI   qword ?       ; 5
  OrigRBP   qword ?       ; 6
  OrigRSP   qword ?       ; 7
  OrigRIP   qword ?       ; 7
  OrigR8    qword ?       ; 8
  OrigR9    qword ?       ; 9
  OrigR10   qword ?       ; 10
  OrigR11   qword ?       ; 11
  OrigR12   qword ?       ; 12
  OrigR13   qword ?       ; 13
  OrigR14   qword ?       ; 14
  OrigR15   qword ?       ; 15
  OrigCS    qword ?       ; 16
  OrigDS    qword ?       ; 16
  OrigES    qword ?       ; 16
  OrigFS    qword ?       ; 16
  OrigGS    qword ?       ; 16
  OrigSS    qword ?       ; 16
  OrigDR0   qword ?       ; 17
  OrigDR1   qword ?       ; 17
  OrigDR2   qword ?       ; 17
  OrigDR3   qword ?       ; 17
  OrigDR6   qword ?       ; 17
  OrigDR7   qword ?       ; 17
  FxState   db 512 dup(?) ; fpu state
stack ends

extern IsrInt1Original : qword
extern IsrInt3Original : qword
extern IsrInt14Original : qword

extern KmInt1Payload : proc
extern KmInt3Payload : proc
extern KmInt14Payload : proc

.code

KmInt1Trap proc
  call KmInt1Payload
  jmp IsrInt1Original
KmInt1Trap endp

KmInt3Trap proc
  call KmInt3Payload
  jmp IsrInt3Original
KmInt3Trap endp

KmInt14Trap proc
  ; push an errorcode on the stack
  sub rsp, 4096
  cld
  ; stack is aligned at this point
  sub rsp, sizeof stack
  ; lea rbp, (stack ptr [rsp]).OrigRAX ???
  mov (stack ptr [rsp]).OrigRAX, rax
  mov (stack ptr [rsp]).OrigRBX, rbx
  mov (stack ptr [rsp]).OrigRCX, rcx
  mov (stack ptr [rsp]).OrigRDX, rdx
  mov (stack ptr [rsp]).OrigRSI, rsi
  mov (stack ptr [rsp]).OrigRDI, rdi
  mov (stack ptr [rsp]).OrigRBP, rbp
  mov (stack ptr [rsp]).OrigRSP, rsp
  mov (stack ptr [rsp]).OrigR8, r8
  mov (stack ptr [rsp]).OrigR9, r9
  mov (stack ptr [rsp]).OrigR10, r10
  mov (stack ptr [rsp]).OrigR11, r11
  mov (stack ptr [rsp]).OrigR12, r12
  mov (stack ptr [rsp]).OrigR13, r13
  mov (stack ptr [rsp]).OrigR14, r14
  mov (stack ptr [rsp]).OrigR15, r15
  ; store FPU state
  ; swapgs
  ; call payload
  mov rcx, rbp
  call KmInt14Payload
  ; stack unwind
  add rsp, sizeof stack
  add rsp, 4096
  ; call original interrupt
  jmp IsrInt14Original
KmInt14Trap endp

end
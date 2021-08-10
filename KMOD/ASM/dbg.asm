; RCX: 1st integer argument
; RDX: 2nd integer argument
; R8: 3rd integer argument
; R9: 4th integer argument

jumpback struct
  A qword ?
  S word  ?
jumpback ends

stack struct
  ScratchSpace  qword ?
  ScratchSpace2 qword ?
  ScratchSpace3 qword ?
  ScratchSpace4 qword ?
  OrigMxcsr     qword ?
  OrigRAX       qword ?       ; 0
  OrigRBX       qword ?       ; 1
  OrigRCX       qword ?       ; 2
  OrigRDX       qword ?       ; 3
  OrigRSI       qword ?       ; 4
  OrigRDI       qword ?       ; 5
  OrigRBP       qword ?       ; 6
  Origrsp       qword ?       ; 7 not really 'original'
  OrigR8        qword ?       ; 8
  OrigR9        qword ?       ; 9
  OrigR10       qword ?       ; 10
  OrigR11       qword ?       ; 11
  OrigR12       qword ?       ; 12
  OrigR13       qword ?       ; 13
  OrigR14       qword ?       ; 14
  OrigR15       qword ?       ; 15
  OrigES        qword ?       ; 16
  OrigDS        qword ?       ; 17
  OrigSS        qword ?       ; 18
  FxSaveSpace   db 512 dup(?) ; fpu state
stack ends

.code

extern Int1CEntry : proc
extern Int1Jumpback : jumpback

GetCS proc
  mov ax,cs
  ret
getCS endp

Int1AsmEntry proc
  ; save stack position
  push [Int1Jumpback.A] ; push an errorcode on the stack so the stackindex enum type can stay the same relative to interrupts that do have an errorcode (int 14).  Also helps with variable interrupt handlers
  sub rsp,4096
  cld
  ; stack is aligned at this point
  sub rsp,sizeof stack
  mov (stack ptr [rsp]).OrigRBP,rbp
  lea rbp,(stack ptr [rsp]).OrigRAX
  mov (stack ptr [rsp]).OrigRAX,rax
  mov (stack ptr [rsp]).OrigRBX,rbx
  mov (stack ptr [rsp]).OrigRCX,rcx
  mov (stack ptr [rsp]).OrigRDX,rdx
  mov (stack ptr [rsp]).OrigRSI,rsi
  mov (stack ptr [rsp]).OrigRDI,rdi
  mov (stack ptr [rsp]).Origrsp,rsp
  mov (stack ptr [rsp]).OrigR8,r8
  mov (stack ptr [rsp]).OrigR9,r9
  mov (stack ptr [rsp]).OrigR10,r10
  mov (stack ptr [rsp]).OrigR11,r11
  mov (stack ptr [rsp]).OrigR12,r12
  mov (stack ptr [rsp]).OrigR13,r13
  mov (stack ptr [rsp]).OrigR14,r14
  mov (stack ptr [rsp]).OrigR15,r15
  fxsave (stack ptr [rsp]).FxSaveSpace
  mov ax,ds
  mov word ptr (stack ptr [rsp]).OrigDS,ax
  mov ax,es
  mov word ptr (stack ptr [rsp]).OrigES,ax
  mov ax,ss
  mov word ptr (stack ptr [rsp]).OrigSS,ax
  mov ax,2bh
  mov ds,ax
  mov es,ax
  mov ax,18h
  mov ss,ax
  ; rbp = pointer to OrigRAX
  cmp qword ptr [rbp+8*21+512+4096],10h
  je SkipSwap1 ; if so, skip the SWAPGS
  swapgs ; swap gs with the kernel version
SkipSwap1:
  stmxcsr dword ptr (stack ptr [rsp]).OrigMxcsr
  mov (stack ptr [rsp]).ScratchSpace2,1f80h
  ldmxcsr dword ptr (stack ptr [rsp]).ScratchSpace2
  mov rcx,rbp
  call Int1CEntry
  ldmxcsr dword ptr (stack ptr [rsp]).OrigMxcsr
  cmp qword ptr [rsp+8*21+512+4096],10h ; was it a kernel interrupt ?
  je SkipSwap2 ; if so, skip the swap gs part
  swapgs ; swap back
SkipSwap2:
  cmp al,1
  ; restore state
  fxrstor (stack ptr [rsp]).FxSaveSpace
  mov ax,word ptr (stack ptr [rsp]).OrigDS
  mov ds,ax
  mov ax,word ptr (stack ptr [rsp]).OrigES
  mov es,ax
  mov ax,word ptr (stack ptr [rsp]).OrigSS
  mov ss,ax
  mov rax,(stack ptr [rsp]).OrigRAX
  mov rbx,(stack ptr [rsp]).OrigRBX
  mov rcx,(stack ptr [rsp]).OrigRCX
  mov rdx,(stack ptr [rsp]).OrigRDX
  mov rsi,(stack ptr [rsp]).OrigRSI
  mov rdi,(stack ptr [rsp]).OrigRDI
  mov r8, (stack ptr [rsp]).OrigR8
  mov r9, (stack ptr [rsp]).OrigR9
  mov r10,(stack ptr [rsp]).OrigR10
  mov r11,(stack ptr [rsp]).OrigR11
  mov r12,(stack ptr [rsp]).OrigR12
  mov r13,(stack ptr [rsp]).OrigR13
  mov r14,(stack ptr [rsp]).OrigR14
  mov r15,(stack ptr [rsp]).OrigR15
  je SkipOrigInt1
  ; stack unwind
  mov rbp,(stack ptr [rsp]).OrigRBP
  add rsp,sizeof stack
  add rsp,4096
  ; at this point [rsp] holds the original int1 handler
  ret ; used to be add rsp,8 ;+8 for the push 0
  ; todo: do a jmp [Int1JumpBackLocationCPUNR] and have 256 Int1JumpBackLocationCPUNR's and each cpu goes to it's own interrupt1_asmentry[cpunr]
  ; jmp [Int1JumpBackLocation.A] ;<-works fine
SkipOrigInt1:
  ; stack unwind
  mov rbp,(stack ptr [rsp]).OrigRBP
  add rsp,sizeof stack
  add rsp,4096
  add rsp,8
  iretq
Int1AsmEntry endp

end
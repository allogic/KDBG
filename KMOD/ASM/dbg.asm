; RCX: 1st integer argument
; RDX: 2nd integer argument
; R8: 3rd integer argument
; R9: 4th integer argument

JUMPBACK STRUCT
	A QWORD ?
	S WORD ?
JUMPBACK ENDS

ASMENTRY_STACK STRUCT
	ScratchSpace	QWORD ?
	ScratchSpace2	QWORD ?
	ScratchSpace3	QWORD ?
	ScratchSpace4	QWORD ?
	OrigMxcsr			QWORD ?
	OrigRAX				QWORD ? ; 0
	OrigRBX				QWORD ? ; 1
	OrigRCX				QWORD ? ; 2
	OrigRDX				QWORD ? ; 3
	OrigRSI				QWORD ? ; 4
	OrigRDI				QWORD ? ; 5
	OrigRBP				QWORD ? ; 6
	OrigRSP				QWORD ? ; 7 not really 'original'
	OrigR8				QWORD ? ; 8
	OrigR9				QWORD ? ; 9
	OrigR10				QWORD ? ; 10
	OrigR11				QWORD ? ; 11
	OrigR12				QWORD ? ; 12
	OrigR13				QWORD ? ; 13
	OrigR14				QWORD ? ; 14
	OrigR15				QWORD ? ; 15
	OrigES				QWORD ? ; 16
	OrigDS				QWORD ?	; 17
	OrigSS				QWORD ?	; 18
	FxSaveSpace   DB 512 DUP(?) ; fpu state
ASMENTRY_STACK ENDS

_TEXT SEGMENT

EXTERN Int1CEntry : PROC
EXTERN Int1JumpBack : JUMPBACK

Int1AEntry PROC
  ; save stack position
  PUSH [Int1JumpBack.A] ; push an errorcode on the stack so the stackindex enum type can stay the same relative to interrupts that do have an errorcode (int 14).  Also helps with variable interrupt handlers
  SUB RSP,4096
  CLD
	; stack is aligned at this point
	SUB RSP, SIZEOF ASMENTRY_STACK
	MOV (ASMENTRY_STACK PTR [RSP]).OrigRBP,RBP
	LEA RBP,(ASMENTRY_STACK PTR [RSP]).OrigRAX
	MOV (ASMENTRY_STACK PTR [RSP]).OrigRAX,RAX
	MOV (ASMENTRY_STACK PTR [RSP]).OrigRBX,RBX
	MOV (ASMENTRY_STACK PTR [RSP]).OrigRCX,RCX
	MOV (ASMENTRY_STACK PTR [RSP]).OrigRDX,RDX
	MOV (ASMENTRY_STACK PTR [RSP]).OrigRSI,RSI
	MOV (ASMENTRY_STACK PTR [RSP]).OrigRDI,RDI
	MOV (ASMENTRY_STACK PTR [RSP]).OrigRSP,RSP
	MOV (ASMENTRY_STACK PTR [RSP]).OrigR8,R8
	MOV (ASMENTRY_STACK PTR [RSP]).OrigR9,R9
	MOV (ASMENTRY_STACK PTR [RSP]).OrigR10,R10
	MOV (ASMENTRY_STACK PTR [RSP]).OrigR11,R11
	MOV (ASMENTRY_STACK PTR [RSP]).OrigR12,R12
	MOV (ASMENTRY_STACK PTR [RSP]).OrigR13,R13
	MOV (ASMENTRY_STACK PTR [RSP]).OrigR14,R14
	MOV (ASMENTRY_STACK PTR [RSP]).OrigR15,R15
	FXSAVE (ASMENTRY_STACK PTR [RSP]).FxSaveSpace
	MOV AX,DS
	MOV WORD PTR (ASMENTRY_STACK PTR [RSP]).OrigDS,AX
	MOV AX,ES
	MOV WORD PTR (ASMENTRY_STACK PTR [RSP]).OrigES,AX
	MOV AX,SS
	MOV WORD PTR (ASMENTRY_STACK PTR [RSP]).OrigSS,AX
	MOV	AX,2BH
	MOV DS,AX
	MOV ES,AX
	MOV AX,18H
	; RBP = pointer to OrigRAX
	CMP QWORD PTR [RBP+8*21+512+4096],10H
	JE SkipSwap1 ; if so, skip the SWAPGS
	SWAPGS  ; swap gs with the kernel version
SkipSwap1:
	STMXCSR	DWORD PTR (ASMENTRY_STACK PTR [RSP]).OrigMxcsr
	MOV (ASMENTRY_STACK PTR [RSP]).ScratchSpace2,1F80H
	LDMXCSR	DWORD PTR (ASMENTRY_STACK PTR [RSP]).ScratchSpace2
	MOV RCX,RBP
	CALL Int1CEntry
	LDMXCSR	DWORD PTR (ASMENTRY_STACK PTR [RSP]).OrigMxcsr
	CMP QWORD PTR [RSP+8*21+512+4096],10H ; was it a kernel interrupt ?
	JE SkipSwap2 ; if so, skip the swap gs part
	swapgs ; swap back
SkipSwap2:
Int1AEntry ENDP

_TEXT ENDS
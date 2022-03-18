IsrHook struct
  Active byte ?
  Original qword ?
  Current qword ?
IsrHook ends

.code

extern MyInterruptPayload : proc
extern IsrHooks : IsrHook

KmInterruptTrap proc
  call MyInterruptPayload
  jmp [IsrHooks.Original]
KmInterruptTrap endp

end
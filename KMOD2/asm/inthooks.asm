IsrHook struct
  Active byte ?
  Original qword ?
  Current qword ?
IsrHook ends

.code

extern IsrHooks : IsrHook

extern KmInt1Payload : proc
extern KmInt3Payload : proc
extern KmInt14Payload : proc

KmInt1Trap proc
  call KmInt1Payload
  jmp (IsrHooks + 1 * (SIZEOF IsrHook)).Original
KmInt1Trap endp

KmInt3Trap proc
  call KmInt3Payload
  jmp (IsrHooks + 3 * (SIZEOF IsrHook)).Original
KmInt3Trap endp

KmInt14Trap proc
  call KmInt14Payload
  jmp (IsrHooks + 14 * (SIZEOF IsrHook)).Original
KmInt14Trap endp

end
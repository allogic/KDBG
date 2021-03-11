# KDBG
The windows kernel debugger consists of to parts, KDRV which is the kernel driver handling ring3 request and KCLI; the command line interface for the driver.
It originated due to lack of insufficient useability with CheatEngine's DBVM driver while debugging games running under certain AntiCheat software.

## Build
Open the VisualStudio solution and build for `Debug` or `Release` bitness `x64`.

## Install
You can start or stop the driver via tools like `kdu.exe` which will turn off `Driver Signature Enforcement` temporarily.
```
.\kdu.exe -dse 0
sc.exe start KDRV
.\kdu.exe -dse 6
```

## Usage
Make sure KDRV is running on your system. After that you can issue a variety of commands some of which are currently under development.

### Dump Kernel Images
```
.\KCLI.exe /DumpKernelImages
FFFFF8061B200000 \SystemRoot\system32\ntoskrnl.exe
FFFFF8061B15C000 \SystemRoot\system32\hal.dll
FFFFF8061C600000 \SystemRoot\system32\kd.dll
FFFFF8061C610000 \SystemRoot\system32\mcupdate_GenuineIntel.dll
FFFFF8061C870000 \SystemRoot\System32\drivers\msrpc.sys
FFFFF8061C840000 \SystemRoot\System32\drivers\ksecdd.sys
FFFFF8061C820000 \SystemRoot\System32\drivers\werkernel.sys
```
### Reading Kernel Memory
```
.\KCLI.exe /ReadKernel ntoskrnl.exe NtOpenProcess 0 42 16
0x00000000 48 83 EC 38 65 48 8B 04 25 88 01 00 00 44 8A 90
0x0000000F 32 02 00 00 44 88 54 24 28 44 88 54 24 20 E8 3D
0x0000001F F7 FF FF 48 83 C4 38 C3 CC CC
0x0:    sub     rsp, 0x38
0x4:    mov     rax, qword ptr gs:[0x188]
0xD:    mov     r10b, byte ptr [rax + 0x232]
0x14:   mov     byte ptr [rsp + 0x28], r10b
0x19:   mov     byte ptr [rsp + 0x20], r10b
0x1E:   call    0xfffffffffffff760
0x23:   add     rsp, 0x38
0x27:   ret
0x28:   int3
0x29:   int3
```
### Writing Kernel Memory
```
.\KCLI.exe /WriteKernel ntoskrnl.exe NtOpenProcess 27 2 90C3
0x00000000 48 83 EC 38 65 48 8B 04 25 88 01 00 00 44 8A 90
0x0000000F 32 02 00 00 44 88 54 24 28 44 88 54 24 20 E8 3D
0x0000001F F7 FF FF 48 83 C4 38 90 C3 CC
0x0:    sub     rsp, 0x38
0x4:    mov     rax, qword ptr gs:[0x188]
0xD:    mov     r10b, byte ptr [rax + 0x232]
0x14:   mov     byte ptr [rsp + 0x28], r10b
0x19:   mov     byte ptr [rsp + 0x20], r10b
0x1E:   call    0xfffffffffffff760
0x23:   add     rsp, 0x38
0x27:   nop
0x28:   ret
0x29:   int3
```

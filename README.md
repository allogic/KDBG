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
### Dump User Images
```
.\KCLI.exe /DumpUserImages
Not implemented yet!
```
### Scan User Memory
```
.\KCLI.exe /ScanMemory explorer.exe explorer.exe 9090909090
Not implemented yet!
```
### Reading Kernel Memory
```
.\KCLI.exe /ReadKernel ntoskrnl.exe NtOpenProcess 0 64 32
0x00000000 48 83 EC 38 65 48 8B 04 25 88 01 00 00 44 8A 90 32 02 00 00 44 88 54 24 28 44 88 54 24 20 E8 3D
0x0000001F F7 FF FF 48 83 C4 38 C3 CC CC CC CC CC CC CC CC 48 89 5C 24 18 56 48 83 EC 20 48 89 7C 24 38 48

0x00000000 48 83 EC 38 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. sub rsp, 0x38
0x00000004 65 48 8B 04 25 88 01 00 00 .. .. .. .. .. .. .. .. .. .. .. mov rax, qword ptr gs:[0x188]
0x0000000D 44 8A 90 32 02 00 00 .. .. .. .. .. .. .. .. .. .. .. .. .. mov r10b, byte ptr [rax + 0x232]
0x00000014 44 88 54 24 28 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. mov byte ptr [rsp + 0x28], r10b
0x00000019 44 88 54 24 20 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. mov byte ptr [rsp + 0x20], r10b
0x0000001E E8 3D F7 FF FF .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. call 0xfffffffffffff760
0x00000023 48 83 C4 38 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. add rsp, 0x38
0x00000027 C3 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ret
0x00000028 CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x00000029 CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000002A CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000002B CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000002C CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000002D CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000002E CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000002F CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x00000030 48 89 5C 24 18 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. mov qword ptr [rsp + 0x18], rbx
0x00000035 56 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. push rsi
0x00000036 48 83 EC 20 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. sub rsp, 0x20
0x0000003A 48 89 7C 24 38 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. mov qword ptr [rsp + 0x38], rdi
```
### Writing Kernel Memory
```
.\KCLI.exe /WriteKernel ntoskrnl.exe NtOpenProcess 27 2 90C3
0x00000000 48 83 EC 38 65 48 8B 04 25 88 01 00 00 44 8A 90 32 02 00 00 44 88 54 24 28 44 88 54 24 20 E8 3D
0x0000001F F7 FF FF 48 83 C4 38 90 C3 CC CC CC CC CC CC CC 48 89 5C 24 18 56 48 83 EC 20 48 89 7C 24 38 48

0x00000000 48 83 EC 38 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. sub rsp, 0x38
0x00000004 65 48 8B 04 25 88 01 00 00 .. .. .. .. .. .. .. .. .. .. .. mov rax, qword ptr gs:[0x188]
0x0000000D 44 8A 90 32 02 00 00 .. .. .. .. .. .. .. .. .. .. .. .. .. mov r10b, byte ptr [rax + 0x232]
0x00000014 44 88 54 24 28 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. mov byte ptr [rsp + 0x28], r10b
0x00000019 44 88 54 24 20 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. mov byte ptr [rsp + 0x20], r10b
0x0000001E E8 3D F7 FF FF .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. call 0xfffffffffffff760
0x00000023 48 83 C4 38 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. add rsp, 0x38
0x00000027 90 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. nop
0x00000028 C3 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ret
0x00000029 CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000002A CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000002B CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000002C CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000002D CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000002E CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000002F CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x00000030 48 89 5C 24 18 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. mov qword ptr [rsp + 0x18], rbx
0x00000035 56 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. push rsi
0x00000036 48 83 EC 20 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. sub rsp, 0x20
0x0000003A 48 89 7C 24 38 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. mov qword ptr [rsp + 0x38], rdi
```
### Reading User Memory
```
.\KCLI.exe /ReadUser explorer.exe explorer.exe 1000 64 32
0x00001000 48 83 EC 28 E8 BF 9A 09 00 48 8D 0D A0 AE 0B 00 48 83 C4 28 E9 CF AA 09 00 CC CC CC CC CC CC CC
0x0000101F 48 83 EC 28 E8 4F 9B 09 00 48 8D 0D A0 AE 0B 00 48 83 C4 28 E9 AF AA 09 00 CC CC CC CC CC CC CC

0x00001000 48 83 EC 28 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. sub rsp, 0x28
0x00001004 E8 BF 9A 09 00 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. call 0x9aac8
0x00001009 48 8D 0D A0 AE 0B 00 .. .. .. .. .. .. .. .. .. .. .. .. .. lea rcx, [rip + 0xbaea0]
0x00001010 48 83 C4 28 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. add rsp, 0x28
0x00001014 E9 CF AA 09 00 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. jmp 0x9bae8
0x00001019 CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000101A CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000101B CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000101C CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000101D CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000101E CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000101F CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x00001020 48 83 EC 28 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. sub rsp, 0x28
0x00001024 E8 4F 9B 09 00 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. call 0x9ab78
0x00001029 48 8D 0D A0 AE 0B 00 .. .. .. .. .. .. .. .. .. .. .. .. .. lea rcx, [rip + 0xbaea0]
0x00001030 48 83 C4 28 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. add rsp, 0x28
0x00001034 E9 AF AA 09 00 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. jmp 0x9bae8
0x00001039 CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000103A CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000103B CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000103C CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000103D CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000103E CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000103F CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
```
### Writing User Memory
```
.\KCLI.exe /WriteUser explorer.exe explorer.exe 101A 5 9090909090
0x00001000 48 83 EC 28 E8 BF 9A 09 00 48 8D 0D A0 AE 0B 00 48 83 C4 28 E9 CF AA 09 00 CC 90 90 90 90 90 CC
0x0000101F 48 83 EC 28 E8 4F 9B 09 00 48 8D 0D A0 AE 0B 00 48 83 C4 28 E9 AF AA 09 00 CC CC CC CC CC CC CC

0x00001000 48 83 EC 28 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. sub rsp, 0x28
0x00001004 E8 BF 9A 09 00 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. call 0x9aac8
0x00001009 48 8D 0D A0 AE 0B 00 .. .. .. .. .. .. .. .. .. .. .. .. .. lea rcx, [rip + 0xbaea0]
0x00001010 48 83 C4 28 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. add rsp, 0x28
0x00001014 E9 CF AA 09 00 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. jmp 0x9bae8
0x00001019 CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000101A 90 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. nop
0x0000101B 90 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. nop
0x0000101C 90 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. nop
0x0000101D 90 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. nop
0x0000101E 90 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. nop
0x0000101F CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x00001020 48 83 EC 28 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. sub rsp, 0x28
0x00001024 E8 4F 9B 09 00 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. call 0x9ab78
0x00001029 48 8D 0D A0 AE 0B 00 .. .. .. .. .. .. .. .. .. .. .. .. .. lea rcx, [rip + 0xbaea0]
0x00001030 48 83 C4 28 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. add rsp, 0x28
0x00001034 E9 AF AA 09 00 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. jmp 0x9bae8
0x00001039 CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000103A CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000103B CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000103C CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000103D CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000103E CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
0x0000103F CC .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. int3
```

## Memory Scanning
Scanning features are currently under development. Feel free to support this project by issuing pull requests.
Pull requests do not follow any guidlines currently as they will be merged by and only by `allogic`.

### Scanning Features
```
- Similar to eg. CoSMOS/CheatEngine
```

## Debugging
Debug features are currently under development. Feel free to support this project by issuing pull requests.
Pull requests do not follow any guidlines currently as they will be merged by and only by `allogic`.

### Debug Features
```
- Suspend/Resume threads
- View hardware registers
- Set hard and software breakpoints
```
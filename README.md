# KDBG
The windows kernel debugger consists of two parts, KMOD which is the kernel driver handling ring3 request and KCLI; the command line interface for the driver.
It originated due to insufficient useability with CheatEngine's DBVM driver while debugging games running under certain AntiCheat software.
The main goal now is to transform KDBG into a fully functional debugger.

## Build
Open the VisualStudio solution and build for `Debug` or `Release` bitness `x64`.

## Install
You can start or stop the driver via tools like `kdu.exe` which will turn off `Driver Signature Enforcement` temporarily.
```
.\kdu.exe -dse 0
sc.exe start/stop KMOD
.\KCLI.exe <PID>
.\kdu.exe -dse 6
```

## Features
 * WriteMemoryProcess
 * WriteMemoryKernel
 * ReadMemoryProcess
 * ReadMemoryKernel
 * ReadModulesProcess
 * ReadModulesKernel
 * ReadThreadsProcess (not implemented yet)
 * TraceContextStart (not implemented yet)
 * TraceContextStop (not implemented yet)
 * DebugBreakpointSet (not implemented yet)
 * DebugBreakpointRem (not implemented yet)

### WriteMemoryProcess
Syntax: `.\KCLI.exe /WriteMemoryProcess [ProcessName] [ImageName] [Offset(hex)] [Size(dec)] [Bytes(hex)]`
Example: `.\KCLI.exe /WriteMemoryProcess taskmgr.exe taskmgr.exe 40000 3 909090`

### WriteMemoryKernel
Syntax: `.\KCLI.exe /WriteMemoryKernel [ImageName] [Offset(hex)] [Size(dec)] [Bytes(hex)]`
Example: `.\KCLI.exe /WriteMemoryKernel ntoskrnl.exe 40000 3 909090`

### ReadMemoryProcess
Syntax: `.\KCLI.exe /ReadMemoryProcess [ProcessName] [ImageName] [Offset(hex)] [Size(dec)]`
Example: `.\KCLI.exe /ReadMemoryProcess taskmgr.exe taskmgr.exe 40000 32`

0x00040000 FD FF 48 FF 15 17 57 09 00 0F 1F 44 00 00 8B 43
0x00040010 3C E9 A1 93 FD FF 4C 89 7D 48 BE 02 00 07 80 E9

0x00040000 FD .. .. .. .. .. .. .. .. .. .. std
0x00040001 FF 48 FF .. .. .. .. .. .. .. .. dec dword ptr [rax - 1]
0x00040004 15 17 57 09 00 .. .. .. .. .. .. adc eax, 0x95717
0x00040009 0F 1F 44 00 00 .. .. .. .. .. .. nop dword ptr [rax + rax]
0x0004000E 8B 43 3C .. .. .. .. .. .. .. .. mov eax, dword ptr [rbx + 0x3c]
0x00040011 E9 A1 93 FD FF .. .. .. .. .. .. jmp 0x193b7
0x00040016 4C 89 7D 48 .. .. .. .. .. .. .. mov qword ptr [rbp + 0x48], r15
0x0004001A BE 02 00 07 80 .. .. .. .. .. .. mov esi, 0x80070002

### ReadMemoryKernel
Syntax: `.\KCLI.exe /ReadMemoryKernel [ImageName] [Offset(hex)] [Size(dec)]`
Example: `.\KCLI.exe /ReadMemoryKernel ntoskrnl.exe 40000 32`

0x00040000 63 00 74 00 00 00 00 00 5C 00 52 00 45 00 47 00
0x00040010 49 00 53 00 54 00 52 00 59 00 5C 00 55 00 53 00

0x00040000 63 00 .. .. .. .. .. .. .. .. .. movsxd rax, dword ptr [rax]
0x00040002 74 00 .. .. .. .. .. .. .. .. .. je 0x40004
0x00040004 00 00 .. .. .. .. .. .. .. .. .. add byte ptr [rax], al
0x00040006 00 00 .. .. .. .. .. .. .. .. .. add byte ptr [rax], al
0x00040008 5C .. .. .. .. .. .. .. .. .. .. pop rsp
0x00040009 00 52 00 .. .. .. .. .. .. .. .. add byte ptr [rdx], dl
0x0004000C 45 00 47 00 .. .. .. .. .. .. .. add byte ptr [r15], r8b
0x00040010 49 00 53 00 .. .. .. .. .. .. .. add byte ptr [r11], dl
0x00040014 54 .. .. .. .. .. .. .. .. .. .. push rsp
0x00040015 00 52 00 .. .. .. .. .. .. .. .. add byte ptr [rdx], dl
0x00040018 59 .. .. .. .. .. .. .. .. .. .. pop rcx
0x00040019 00 5C 00 55 .. .. .. .. .. .. .. add byte ptr [rax + rax + 0x55], bl
0x0004001D 00 53 00 .. .. .. .. .. .. .. .. add byte ptr [rbx], dl

### ReadModulesProcess
Syntax: `.\KCLI.exe /ReadModulesProcess [ProcessName] [Size(dec)]`
Example: `.\KCLI.exe /ReadModulesProcess taskmgr.exe 10`

  Start            End                    Size Name
----------------------------------------------------------------
  00007FFAD0740000 00007FFAD07FD000     774144 KERNEL32.DLL
  00007FFACF5B0000 00007FFACF879000    2920448 KERNELBASE.dll
  00007FFACF0A0000 00007FFACF1A0000    1048576 ucrtbase.dll
  00007FFACFBB0000 00007FFACFC7D000     839680 OLEAUT32.dll
  00007FFACF300000 00007FFACF39D000     643072 msvcp_win.dll
  00007FFACFD30000 00007FFAD0085000    3493888 combase.dll
  00007FFAD0D30000 00007FFAD0E5B000    1224704 RPCRT4.dll
  00007FFACF8B0000 00007FFACF8B8000      32768 NSI.dll
  00007FFAD0E60000 00007FFAD0EB5000     348160 SHLWAPI.dll
  00007FFAD1740000 00007FFAD17DE000     647168 msvcrt.dll

### ReadModulesKernel
Syntax: `.\KCLI.exe /ReadModulesKernel [Size(dec)]`
Example: `.\KCLI.exe /ReadModulesKernel 10`

  Start            End                    Size Name
----------------------------------------------------------------
  FFFFF80457800000 FFFFF80458846000   17063936 ntoskrnl.exe
  FFFFF80454E70000 FFFFF80454E76000      24576 hal.dll
  FFFFF80454E80000 FFFFF80454E8B000      45056 kd.dll
  FFFFF80454BE0000 FFFFF80454E6F000    2682880 mcupdate_GenuineIntel.dll
  FFFFF80454EC0000 FFFFF80454F29000     430080 CLFS.SYS
  FFFFF80454E90000 FFFFF80454EB7000     159744 tm.sys
  FFFFF80454F30000 FFFFF80454F4A000     106496 PSHED.dll
  FFFFF80454F50000 FFFFF80454F5B000      45056 BOOTVID.dll
  FFFFF80454F60000 FFFFF80454FCF000     454656 FLTMGR.SYS
  FFFFF8045A550000 FFFFF8045A5B2000     401408 msrpc.sys

### ReadThreadsProcess
Syntax: `.\KCLI.exe /ReadThreadsProcess [Size(dec)]`

### TraceContextStart
Syntax: `.\KCLI.exe /TraceContextStart [Address(hex)]`

### TraceContextStop
Syntax: `.\KCLI.exe /TraceContextStop [Id(dec)]`

### DebugBreakpointSet
Syntax: `.\KCLI.exe /DebugBreakpointSet [Base(hex)] [Type(0=Software|1=Hardware)]`

### DebugBreakpointRem
Syntax: `.\KCLI.exe /DebugBreakpointRem [Base(hex)]`
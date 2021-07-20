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
sc.exe start KMOD
.\KCLI.exe <PID>
.\kdu.exe -dse 6
```

![KCLI.exe](/res/kcli.png)
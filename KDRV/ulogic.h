#ifndef _ULOGIC_H
#define _ULOGIC_H

#include "global.h"
#include "undoc.h"

NTSTATUS GetUserImages(PSYSTEM_PROCESS_INFORMATION images, ULONG size);
NTSTATUS GetUserImageBase(ULONG pid, PWCHAR moduleName, PVOID& imageBase);

NTSTATUS TryReadUserMemory(ULONG pid, PVOID base, PBYTE buffer, ULONG bufferSize);
NTSTATUS TryWriteUserMemory(ULONG pid, PVOID base, PBYTE buffer, ULONG bufferSize);

NTSTATUS ScanUserMemory(ULONG pid, PVOID base, PBYTE pattern, ULONG patternSize, PVOID patternBase);

#endif
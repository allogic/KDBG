#ifndef _MEM_H
#define _MEM_H

#include "global.h"

NTSTATUS TryReadKernelMemory(PVOID base, PBYTE buffer, ULONG bufferSize);
NTSTATUS TryReadUserMemory(ULONG pid, PVOID base, PBYTE buffer, ULONG bufferSize);

NTSTATUS CopyUserMemory(PVOID destination, PVOID source, ULONG size);

NTSTATUS TryWriteKernelMemory(PVOID base, PBYTE buffer, ULONG bufferSize);
NTSTATUS TryWriteUserMemory(ULONG pid, PVOID base, PBYTE buffer, ULONG bufferSize);

NTSTATUS ScanUserMemory(ULONG pid, PVOID base, PBYTE pattern, ULONG patternSize, PVOID& patternBase);

#endif
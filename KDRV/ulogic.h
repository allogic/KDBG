#ifndef _ULOGIC_H
#define _ULOGIC_H

#include "global.h"

NTSTATUS DumpUserImages(ULONG pid, PVOID images);
NTSTATUS GetUserImageBase(ULONG pid, PPVOID imageBase);

NTSTATUS TryReadUserMemory(ULONG pid, PVOID base, PUCHAR buffer, ULONG bufferSize);
NTSTATUS TryWriteUserMemory(ULONG pid, PVOID base, PUCHAR buffer, ULONG bufferSize);

#endif
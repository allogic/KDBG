#ifndef _ULOGIC_H
#define _ULOGIC_H

#include "global.h"
#include "undoc.h"

NTSTATUS GetUserImages(PSYSTEM_PROCESS_INFORMATION images, ULONG size);
NTSTATUS GetUserImageBase(ULONG pid, PVOID& imageBase);

NTSTATUS TryReadUserMemory(ULONG pid, PVOID base, PUCHAR buffer, ULONG bufferSize);
NTSTATUS TryWriteUserMemory(ULONG pid, PVOID base, PUCHAR buffer, ULONG bufferSize);

#endif
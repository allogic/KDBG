#ifndef _KLOGIC_H
#define _KLOGIC_H

#include "global.h"
#include "undoc.h"

NTSTATUS DumpKernelImages(PRTL_PROCESS_MODULES images, ULONG size);
NTSTATUS GetKernelImageBase(PCHAR imageName, PPVOID imageBase);

NTSTATUS TryReadKernelMemory(PVOID base, PUCHAR buffer, ULONG bufferSize);
NTSTATUS TryWriteKernelMemory(PVOID base, PUCHAR buffer, ULONG bufferSize);

#endif
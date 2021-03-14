#ifndef _KLOGIC_H
#define _KLOGIC_H

#include "global.h"
#include "undoc.h"

NTSTATUS GetKernelImages(PRTL_PROCESS_MODULES images, ULONG size);
NTSTATUS GetKernelImageBase(PCHAR imageName, PVOID& imageBase);

NTSTATUS TryReadKernelMemory(PVOID base, PBYTE buffer, ULONG bufferSize);
NTSTATUS TryWriteKernelMemory(PVOID base, PBYTE buffer, ULONG bufferSize);

#endif
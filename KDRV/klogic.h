#ifndef _KLOGIC_H
#define _KLOGIC_H

#include "global.h"

NTSTATUS DumpKernelImages();
NTSTATUS GetKernelImageBase(PCHAR imageName, PPVOID imageBase, PULONG imageSize);

NTSTATUS TryReadKernelMemory(PVOID base, PUCHAR buffer, ULONG bufferSize);
NTSTATUS TryWriteKernelMemory(PVOID base, PUCHAR buffer, ULONG bufferSize);

#endif
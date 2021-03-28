#ifndef _PROC_H
#define _PROC_H

#include "global.h"
#include "undoc.h"
#include "util.h"

NTSTATUS GetKernelImages(PRTL_PROCESS_MODULES images, ULONG size);
NTSTATUS GetUserImages(PSYSTEM_PROCESS_INFORMATION images, ULONG size);

NTSTATUS GetKernelImageBase(PCHAR imageName, PVOID& imageBase);
NTSTATUS GetUserImageBase(ULONG pid, PWCHAR moduleName, PVOID& imageBase);

PLDR_DATA_TABLE_ENTRY GetMainModuleDataTableEntry(PPEB64 peb);

#endif
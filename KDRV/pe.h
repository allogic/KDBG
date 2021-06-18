#ifndef _PE_H
#define _PE_H

#include "global.h"
#include "undoc.h"

ULONG RvaToSection(PIMAGE_NT_HEADERS ntHeaders, ULONG rva);
ULONG RvaToOffset(PIMAGE_NT_HEADERS ntHeaders, ULONG rva, ULONG fileSize);

NTSTATUS GetKernelImageBase(PCHAR imageName, PVOID& imageBase);
NTSTATUS GetUserImageBase(ULONG pid, PWCHAR moduleName, PVOID& imageBase);

PVOID GetPageBase(PVOID imageBase, PULONG imageSize, PVOID ptr);
ULONG GetExportOffset(PVOID imageBase, ULONG imageSize, PCCHAR exportName);

PVOID SanitizeUserPointer(PVOID pointer, SIZE_T size);
PLDR_DATA_TABLE_ENTRY GetMainModuleDataTableEntry(PPEB64 peb);

#endif
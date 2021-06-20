#ifndef _PE_H
#define _PE_H

#include "global.h"
#include "undoc.h"

ULONG RvaToSection(PIMAGE_NT_HEADERS ntHeaders, ULONG rva);
ULONG RvaToOffset(PIMAGE_NT_HEADERS ntHeaders, ULONG rva, ULONG fileSize);

PVOID GetPageBase(PVOID moduleBase, PULONG moduleSize, PVOID ptr);
ULONG GetExportOffset(PVOID moduleBase, ULONG moduleSize, PCCHAR exportName);

#endif
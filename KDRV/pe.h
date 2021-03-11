#ifndef _PE_H
#define _PE_H

#include "global.h"
#include "undoc.h"

#define PE_ERROR_VALUE (ULONG)-1

PLDR_DATA_TABLE_ENTRY GetMainModuleDataTableEntry(PPEB64 peb);

PVOID GetPageBase(PVOID imageBase, PULONG imageSize, PVOID ptr);
ULONG GetExportOffset(PVOID imageBase, ULONG imageSize, PCCHAR exportName);

#endif
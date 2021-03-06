#ifndef _PE_H
#define _PE_H

#include "global.h"

#define PE_ERROR_VALUE (ULONG)-1

PVOID GetPageBase(PVOID imageBase, PULONG imageSize, PVOID ptr);
ULONG GetExportOffset(PVOID imageBase, ULONG imageSize, PCCHAR exportName);

#endif
#ifndef _UTIL_H
#define _UTIL_H

#include "global.h"

NTSTATUS DumpToFile(PWSTR filePath, PVOID bytes, ULONG size);

#endif
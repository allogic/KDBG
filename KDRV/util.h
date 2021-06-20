#ifndef _UTIL_H
#define _UTIL_H

#include "global.h"

NTSTATUS DumpToFile(PUNICODE_STRING path, PVOID bytes, ULONG size);

#endif
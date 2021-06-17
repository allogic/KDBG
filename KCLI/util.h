#ifndef _UTIL_H
#define _UITL_H

#include "global.h"

ULONG GetProcessId(PWCHAR processName);

SIZE_T ArgvLength(PWCHAR argv);
PBYTE ArgvToBytes(PWCHAR argv);
PWCHAR ArgvToWcStr(PWCHAR argv);
PCHAR ArgvToMbStr(PWCHAR argv);

VOID DisassembleBytes(PBYTE bytes, SIZE_T size, SIZE_T offset);

#endif
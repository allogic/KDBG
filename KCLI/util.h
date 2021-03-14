#ifndef _UTIL_H
#define _UITL_H

#include "global.h"

ULONG GetProcessId(PWCHAR processName);

template<typename TYPE>
TYPE* AllocMemory(BOOL zeroMemory, SIZE_T size)
{
  TYPE* result = (TYPE*)malloc(sizeof(TYPE) * size);
  if (result)
    memset(result, 0, size);
  return (TYPE*)result;
}
VOID FreeMemory(PVOID pointer);

SIZE_T ArgvLength(PWCHAR argv);
PBYTE ArgvToBytes(PWCHAR argv);
PWCHAR ArgvToWcStr(PWCHAR argv);
PCHAR ArgvToMbStr(PWCHAR argv);

VOID DisassembleBytes(PBYTE bytes, SIZE_T size);

#endif
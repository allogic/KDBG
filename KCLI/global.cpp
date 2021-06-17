#include "global.h"

VOID FreeMemory(PVOID pointer)
{
  free(pointer);
}
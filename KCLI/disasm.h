#ifndef _DISASM_H
#define _DISASM_H

#include "global.h"

VOID
DisassembleBytes(
  PBYTE bytes,
  ULONG size,
  ULONG offset);

#endif
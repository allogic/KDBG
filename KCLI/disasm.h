/*
* @author allogic
* @file disasm.h
* @brief Generic disassembler.
* @copyright allogic 2021. All Rights Reserved.
*/

#ifndef _DISASM_H
#define _DISASM_H

#include "global.h"

VOID
DisassembleBytes(
  PBYTE bytes,
  ULONG size,
  ULONG offset);

#endif
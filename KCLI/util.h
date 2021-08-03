#ifndef _UTIL_H
#define _UTIL_H

#include "global.h"

ULONG
GetProcessIdFromNameW(
  PCWCHAR processName);

VOID
Utf16ToUtf8(
  PWCHAR utf16,
  PCHAR utf8);

VOID
Utf8ToUtf16(
  PCHAR utf8,
  PWCHAR utf16);

VOID
HexToBytesW(
  PBYTE bytes,
  PWCHAR hex);

#endif
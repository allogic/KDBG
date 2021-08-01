#ifndef _PE_H
#define _PE_H

#include "global.h"
#include "undoc.h"

/*
* PE utilities.
*/

#define KM_PE_ERROR_VALUE (PVOID)-1

USHORT
KmRvaToSection(
  PIMAGE_NT_HEADERS ntHeaders,
  PVOID rva);

ULONG
KmRvaToOffset(
  PIMAGE_NT_HEADERS ntHeaders,
  PVOID rva,
  ULONG imageSize);

ULONG
KmGetImageExportOffset(
  PVOID imageBase,
  ULONG fileSize,
  PCCHAR exportName);

#endif
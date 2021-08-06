/*
* @author allogic
* @file scanner.h
* @brief Memory scanning utilities.
* @copyright allogic 2021. All Rights Reserved.
*/

#ifndef _SCANNER_H
#define _SCANNER_H

#include "global.h"

/*
* Int values.
*/

NTSTATUS
KmScanIntSigned8(
  PVOID base,
  SIZE_T size,
  BYTE value);

NTSTATUS
KmScanIntUnsigned8(
  PVOID base,
  SIZE_T size,
  BYTE value);

NTSTATUS
KmScanIntSigned16(
  PVOID base,
  SIZE_T size,
  PBYTE value);

NTSTATUS
KmScanIntUnsigned16(
  PVOID base,
  SIZE_T size,
  PBYTE value);

NTSTATUS
KmScanIntSigned32(
  PVOID base,
  SIZE_T size,
  PBYTE value);

NTSTATUS
KmScanIntUnsigned32(
  PVOID base,
  SIZE_T size,
  PBYTE value);

/*
* Real values.
*/

NTSTATUS
KmScanReal32(
  PVOID base,
  SIZE_T size,
  PBYTE value);

NTSTATUS
KmScanReal64(
  PVOID base,
  SIZE_T size,
  PBYTE value);

/*
* Byte patterns.
*/

NTSTATUS
KmScanBytes(
  PVOID base,
  SIZE_T size,
  PBYTE bytes,
  ULONG byteCount);

#endif
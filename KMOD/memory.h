#ifndef _MEMORY_H
#define _MEMORY_H

#include "global.h"

/*
* Interlocked memory operations.
*/

NTSTATUS
KmInterlockedMemcpy(
  PVOID dst,
  PVOID src,
  SIZE_T size,
  KPROCESSOR_MODE mode);

/*
* Process relative.
*/

NTSTATUS
KmReadMemoryProcess(
  ULONG pid,
  PVOID base,
  SIZE_T size,
  PVOID buffer);

NTSTATUS
KmWriteMemoryProcess(
  ULONG pid,
  PVOID base,
  SIZE_T size,
  PVOID buffer);

/*
* Kernel relative.
*/

NTSTATUS
KmReadMemoryKernel(
  PVOID base,
  SIZE_T size,
  PVOID buffer);

NTSTATUS
KmWriteMemoryKernel(
  PVOID base,
  SIZE_T size,
  PVOID buffer);

#endif
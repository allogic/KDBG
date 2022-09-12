#ifndef KM_MEMORY_H
#define KM_MEMORY_H

#include <km_core.h>
#include <km_ioctrl.h>

///////////////////////////////////////////////////////////
// Memory utilities
///////////////////////////////////////////////////////////

NTSTATUS
KmReadMemorySafe(
  PVOID dst,
  PVOID src,
  DWORD32 size);

NTSTATUS
KmWriteMemorySafe(
  PVOID dst,
  PVOID src,
  DWORD32 size);

PVOID
KmConvertToSystemAddressSafe(
  PVOID base);

PVOID
KmConvertToUserAddressSafe(
  PVOID base);

///////////////////////////////////////////////////////////
// Memory API
///////////////////////////////////////////////////////////

NTSTATUS
KmReadProcessMemory(
  PREAD_PROCESS_MEMORY request,
  PBYTE bytes);

NTSTATUS
KmReadKernelMemory(
  PREAD_KERNEL_MEMORY request,
  PBYTE bytes);

NTSTATUS
KmWriteProcessMemory(
  PWRITE_PROCESS_MEMORY request);

NTSTATUS
KmWriteKernelMemory(
  PWRITE_KERNEL_MEMORY request);

#endif
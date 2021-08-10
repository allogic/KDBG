#include "memory.h"

NTSTATUS
KmInterlockedMemcpy(
  PVOID dst,
  PVOID src,
  SIZE_T size,
  KPROCESSOR_MODE mode)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  PMDL mdl = IoAllocateMdl(src, size, FALSE, FALSE, NULL);
  if (mdl)
  {
    MmProbeAndLockPages(mdl, mode, IoReadAccess);
    PVOID mappedSrc = MmMapLockedPagesSpecifyCache(mdl, mode, MmNonCached, NULL, FALSE, HighPagePriority);
    if (mappedSrc)
    {
      status = MmProtectMdlSystemAddress(mdl, PAGE_READONLY);
      if (NT_SUCCESS(status))
      {
        __try
        {
          memcpy(dst, mappedSrc, size);
          status = STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
          KM_LOG_ERROR("Something went wrong\n");
        }
      }
      MmUnmapLockedPages(mappedSrc, mdl);
    }
    MmUnlockPages(mdl);
  }
  IoFreeMdl(mdl);
  return status;
}

NTSTATUS
KmWriteMemoryProcess(
  ULONG pid,
  PVOID base,
  SIZE_T size,
  PVOID buffer)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  PEPROCESS process = NULL;
  KAPC_STATE apc;
  status = PsLookupProcessByProcessId((HANDLE)pid, &process);
  if (NT_SUCCESS(status))
  {
    status = STATUS_UNSUCCESSFUL;
    PMDL mdl = IoAllocateMdl(base, size, FALSE, FALSE, NULL);
    if (mdl)
    {
      KeStackAttachProcess(process, &apc);
      __try
      {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        PBYTE mappedBuffer = (PBYTE)MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, HighPagePriority);
        if (mappedBuffer)
        {
          status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
          if (NT_SUCCESS(status))
          {
            memcpy(mappedBuffer, buffer, size);
          }
          MmUnmapLockedPages(mappedBuffer, mdl);
        }
        MmUnlockPages(mdl);
      }
      __except (EXCEPTION_EXECUTE_HANDLER)
      {
        KM_LOG_ERROR("Something went wrong!\n");
        status = STATUS_UNHANDLED_EXCEPTION;
      }
      KeUnstackDetachProcess(&apc);
      IoFreeMdl(mdl);
    }
    ObDereferenceObject(process);
  }
  return status;
}

NTSTATUS
KmWriteMemoryKernel(
  PVOID base,
  SIZE_T size,
  PVOID buffer)
{
  return KmInterlockedMemcpy(base, buffer, size, KernelMode);
}

NTSTATUS
KmReadMemoryProcess(
  ULONG pid,
  PVOID base,
  SIZE_T size,
  PVOID buffer)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  PEPROCESS process = NULL;
  KAPC_STATE apc;
  status = PsLookupProcessByProcessId((HANDLE)pid, &process);
  if (NT_SUCCESS(status))
  {
    status = STATUS_UNSUCCESSFUL;
    PBYTE asyncBuffer = (PBYTE)KmAllocateMemory(TRUE, size);
    if (asyncBuffer)
    {
      PMDL mdl = IoAllocateMdl(base, size, FALSE, FALSE, NULL);
      if (mdl)
      {
        KeStackAttachProcess(process, &apc);
        __try
        {
          MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
          PBYTE mappedBuffer = (PBYTE)MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, HighPagePriority);
          if (mappedBuffer)
          {
            status = MmProtectMdlSystemAddress(mdl, PAGE_READONLY);
            if (NT_SUCCESS(status))
            {
              memcpy(asyncBuffer, mappedBuffer, size);
            }
            MmUnmapLockedPages(mappedBuffer, mdl);
          }
          MmUnlockPages(mdl);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
          KM_LOG_ERROR("Something went wrong!\n");
          status = STATUS_UNHANDLED_EXCEPTION;
        }
        KeUnstackDetachProcess(&apc);
        IoFreeMdl(mdl);
      }
      memcpy(buffer, asyncBuffer, size);
      KmFreeMemory(asyncBuffer);
    }
    ObDereferenceObject(process);
  }
  return status;
}

NTSTATUS
KmReadMemoryKernel(
  PVOID base,
  SIZE_T size,
  PVOID buffer)
{
  return KmInterlockedMemcpy(buffer, base, size, KernelMode);
}
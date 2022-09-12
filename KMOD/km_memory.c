#include <km_memory.h>
#include <km_debug.h>
#include <km_config.h>

///////////////////////////////////////////////////////////
// Memory utilities
///////////////////////////////////////////////////////////

NTSTATUS
KmReadMemorySafe(
  PVOID dst,
  PVOID src,
  DWORD32 size)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;

  // Create MDL for supplied range
  PMDL mdl = IoAllocateMdl(src, size, FALSE, FALSE, NULL);
  if (mdl)
  {
    __try
    {
      // Try lock pages
      MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
      status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
      status = STATUS_INVALID_USER_BUFFER;
    }

    if (NT_SUCCESS(status))
    {
      // Remap to system space address
      PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, HighPagePriority);
      if (mapped)
      {
        // Set page protection
        status = MmProtectMdlSystemAddress(mdl, PAGE_READONLY);
        if (NT_SUCCESS(status))
        {
          // Copy memory
          RtlCopyMemory(dst, mapped, size);
        }

        // Unmap locked pages
        MmUnmapLockedPages(mapped, mdl);
      }

      // Unlock MDL
      MmUnlockPages(mdl);
    }

    // Free MDL
    IoFreeMdl(mdl);
  }

  return status;
}

NTSTATUS
KmWriteMemorySafe(
  PVOID dst,
  PVOID src,
  DWORD32 size)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;

  // Create MDL for supplied range
  PMDL mdl = IoAllocateMdl(dst, size, FALSE, FALSE, NULL);
  if (mdl)
  {
    __try
    {
      // Try lock pages
      MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
      status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
      status = STATUS_INVALID_USER_BUFFER;
    }

    if (NT_SUCCESS(status))
    {
      // Remap to system space address
      PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, HighPagePriority);
      if (mapped)
      {
        // Set page protection
        status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
        if (NT_SUCCESS(status))
        {
          // Copy memory
          RtlCopyMemory(mapped, src, size);
        }

        // Unmap locked pages
        MmUnmapLockedPages(mapped, mdl);
      }

      // Unlock MDL
      MmUnlockPages(mdl);
    }

    // Free MDL
    IoFreeMdl(mdl);
  }

  return status;
}

PVOID
KmConvertToSystemAddressSafe(
  PVOID base)
{
  PVOID mappedBase = base;
  return mappedBase;
}

PVOID
KmConvertToUserAddressSafe(
  PVOID base)
{
  PVOID mappedBase = base;
  return mappedBase;
}

///////////////////////////////////////////////////////////
// Memory API
///////////////////////////////////////////////////////////

NTSTATUS
KmReadProcessMemory(
  PREAD_PROCESS_MEMORY request,
  PBYTE bytes)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;

  __try
  {
    // Allocate buffer to hold bytes while attached to process
    PBYTE buffer = ExAllocatePoolWithTag(NonPagedPool, request->Size, KM_MEMORY_POOL_TAG);
    if (buffer)
    {
      // Zero buffer
      RtlFillMemory(buffer, request->Size, 0);

      // Search process by process id
      PEPROCESS process;
      status = PsLookupProcessByProcessId((HANDLE)request->Pid, &process);
      if (NT_SUCCESS(status))
      {
        // Attach to process
        KAPC_STATE apc;
        KeStackAttachProcess(process, &apc);

        // Copy process memory into supplied kernel space buffer
        status = KmReadMemorySafe(buffer, (PVOID)request->Base, request->Size);

        // Detach from process
        KeUnstackDetachProcess(&apc);

        // Copy buffer into response
        RtlCopyMemory(bytes, buffer, request->Size);

        // Dereference process handle
        ObDereferenceObject(process);
      }

      // Free buffer
      ExFreePoolWithTag(buffer, KM_MEMORY_POOL_TAG);
    }
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    KD_LOG("Something went wrong\n");
    status = STATUS_UNHANDLED_EXCEPTION;
  }

  return status;
}

NTSTATUS
KmReadKernelMemory(
  PREAD_KERNEL_MEMORY request,
  PBYTE bytes)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;

  __try
  {
    // Directly copy kernel memory into response
    status = KmReadMemorySafe(bytes, (PVOID)request->Base, request->Size);
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    KD_LOG("Something went wrong\n");
    status = STATUS_UNHANDLED_EXCEPTION;
  }

  return status;
}

NTSTATUS
KmWriteProcessMemory(
  PWRITE_PROCESS_MEMORY request)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;

  __try
  {
    // Allocate buffer to hold bytes while attached to process
    PBYTE buffer = ExAllocatePoolWithTag(NonPagedPool, request->Size, KM_MEMORY_POOL_TAG);
    if (buffer)
    {
      // Copy request buffer into kernel space buffer
      RtlCopyMemory(buffer, request->Buffer, request->Size);

      // Search process by process id
      PEPROCESS process;
      status = PsLookupProcessByProcessId((HANDLE)request->Pid, &process);
      if (NT_SUCCESS(status))
      {
        // Attach to process
        KAPC_STATE apc;
        KeStackAttachProcess(process, &apc);

        // Copy supplied kernel space buffer into process memory
        status = KmWriteMemorySafe((PVOID)request->Base, buffer, request->Size);

        // Detach from process
        KeUnstackDetachProcess(&apc);

        // Dereference process handle
        ObDereferenceObject(process);
      }

      // Free buffer
      ExFreePoolWithTag(buffer, KM_MEMORY_POOL_TAG);
    }
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    KD_LOG("Something went wrong\n");
    status = STATUS_UNHANDLED_EXCEPTION;
  }

  return status;
}

NTSTATUS
KmWriteKernelMemory(
  PWRITE_KERNEL_MEMORY request)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;

  __try
  {
    // Directly copy buffer into kernel memory
    status = KmWriteMemorySafe((PVOID)request->Base, request->Buffer, request->Size);
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    KD_LOG("Something went wrong\n");
    status = STATUS_UNHANDLED_EXCEPTION;
  }

  return status;
}
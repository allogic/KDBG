#include "mem.h"

NTSTATUS TryReadKernelMemory(PVOID base, PBYTE buffer, ULONG bufferSize)
{
  NTSTATUS status = STATUS_SUCCESS;
  // Mdl for base addr
  PMDL mdl = IoAllocateMdl(base, bufferSize, FALSE, FALSE, NULL);
  if (!mdl)
  {
    LOG_ERROR("IoAllocateMdl\n");
    return STATUS_ACCESS_VIOLATION;
  }
  __try
  {
    // Lock memory pages
    MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    PVOID mappedBase = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
    // Read memory
    if (mappedBase)
      RtlCopyMemory(buffer, mappedBase, bufferSize);
    // Unlock pages
    MmUnmapLockedPages(mappedBase, mdl);
    MmUnlockPages(mdl);
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    LOG_ERROR("Something went wrong\n");
    status = STATUS_FAIL_CHECK;
  }
  // Cleanup
  IoFreeMdl(mdl);
  return status;
}
NTSTATUS TryReadUserMemory(ULONG pid, PVOID base, PBYTE buffer, ULONG bufferSize)
{
  NTSTATUS status = STATUS_SUCCESS;
  // Find process
  PEPROCESS process = NULL;
  status = PsLookupProcessByProcessId((HANDLE)pid, &process);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("PsLookupProcessByProcessId\n");
    return status;
  }
  // Mdl for base addr
  PMDL mdl = IoAllocateMdl(base, bufferSize, FALSE, FALSE, NULL);
  if (!mdl)
  {
    ObDereferenceObject(process);
    LOG_ERROR("IoAllocateMdl\n");
    return STATUS_ACCESS_VIOLATION;
  }
  // Allocate temporary buffer
  PBYTE asyncBuffer = (PBYTE)RtlAllocateMemory(TRUE, bufferSize);
  if (!asyncBuffer)
  {
    IoFreeMdl(mdl);
    ObDereferenceObject(process);
    LOG_ERROR("IoAllocateMdl\n");
    return STATUS_INVALID_ADDRESS;
  }
  KAPC_STATE apc;
  __try
  {
    // Attach to process
    KeStackAttachProcess(process, &apc);
    // Lock pages
    MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
    // Address mapping
    PBYTE mappedBase = (PBYTE)MmMapLockedPagesSpecifyCache(mdl, UserMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    // Set protection levels
    MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
    // Copy memory into async buffer
    if (mappedBase)
      RtlCopyMemory(asyncBuffer, mappedBase, bufferSize);
    // Unlock pages
    MmUnmapLockedPages(mappedBase, mdl);
    MmUnlockPages(mdl);
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    LOG_ERROR("Something went wrong\n");
    status = STATUS_FAIL_CHECK;
  }
  // Detach from process
  KeUnstackDetachProcess(&apc);
  // Copy kernel buffer to request buffer
  RtlCopyMemory(buffer, asyncBuffer, bufferSize);
  // Cleanup
  RtlFreeMemory(asyncBuffer);
  IoFreeMdl(mdl);
  ObDereferenceObject(process);
  return status;
}

NTSTATUS TryWriteKernelMemory(PVOID base, PBYTE buffer, ULONG bufferSize)
{
  NTSTATUS status = STATUS_SUCCESS;
  // Mdl for base addr
  PMDL mdl = IoAllocateMdl(base, bufferSize, FALSE, FALSE, NULL);
  if (!mdl)
  {
    LOG_ERROR("IoAllocateMdl\n");
    return STATUS_ACCESS_VIOLATION;
  }
  __try
  {
    // Lock memory pages
    MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    PVOID mappedBase = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
    // Write memory
    if (mappedBase)
      RtlCopyMemory(mappedBase, buffer, bufferSize);
    // Unlock pages
    MmUnmapLockedPages(mappedBase, mdl);
    MmUnlockPages(mdl);
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    LOG_ERROR("Something went wrong\n");
    status = STATUS_FAIL_CHECK;
  }
  // Cleanup
  IoFreeMdl(mdl);
  return status;
}
NTSTATUS TryWriteUserMemory(ULONG pid, PVOID base, PBYTE buffer, ULONG bufferSize)
{
  NTSTATUS status = STATUS_SUCCESS;
  // Find process
  PEPROCESS process = NULL;
  status = PsLookupProcessByProcessId((HANDLE)pid, &process);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("PsLookupProcessByProcessId\n");
    return status;
  }
  // Mdl for base addr
  PMDL mdl = IoAllocateMdl(base, bufferSize, FALSE, FALSE, NULL);
  if (!mdl)
  {
    ObDereferenceObject(process);
    LOG_ERROR("IoAllocateMdl\n");
    return STATUS_ACCESS_VIOLATION;
  }
  // Allocate temporary buffer
  PBYTE asyncBuffer = (PBYTE)RtlAllocateMemory(TRUE, bufferSize);
  if (!asyncBuffer)
  {
    IoFreeMdl(mdl);
    ObDereferenceObject(process);
    LOG_ERROR("IoAllocateMdl\n");
    return STATUS_INVALID_ADDRESS;
  }
  // Copy request buffer to kernel space
  RtlCopyMemory(asyncBuffer, buffer, bufferSize);
  KAPC_STATE apc;
  __try
  {
    // Attach to process
    KeStackAttachProcess(process, &apc);
    // Lock pages
    MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
    // Address mapping
    PBYTE mappedBase = (PBYTE)MmMapLockedPagesSpecifyCache(mdl, UserMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    // Set protection levels
    MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
    // Copy memory from async buffer
    if (mappedBase)
      RtlCopyMemory(mappedBase, asyncBuffer, bufferSize);
    // Unlock pages
    MmUnmapLockedPages(mappedBase, mdl);
    MmUnlockPages(mdl);
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    LOG_ERROR("Something went wrong\n");
    status = STATUS_FAIL_CHECK;
  }
  // Detach from process
  KeUnstackDetachProcess(&apc);
  // Cleanup
  RtlFreeMemory(asyncBuffer);
  IoFreeMdl(mdl);
  ObDereferenceObject(process);
  return status;
}

NTSTATUS ScanUserMemory(ULONG pid, PVOID base, PBYTE pattern, ULONG patternSize, PVOID& patternBase)
{
  UNREFERENCED_PARAMETER(patternBase);
  NTSTATUS status = STATUS_SUCCESS;
  // Find process
  PEPROCESS process = NULL;
  status = PsLookupProcessByProcessId((HANDLE)pid, &process);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("PsLookupProcessByProcessId\n");
    return status;
  }
  // Allocate temporary buffer
  PBYTE asyncBuffer = (PBYTE)RtlAllocateMemory(TRUE, patternSize);
  if (!asyncBuffer)
  {
    ObDereferenceObject(process);
    LOG_ERROR("IoAllocateMdl\n");
    return STATUS_INVALID_ADDRESS;
  }
  // Copy pattern into kernel space
  RtlCopyMemory(asyncBuffer, pattern, patternSize);
  PMDL mdl = NULL;
  KAPC_STATE apc;
  __try
  {
    // Attach to process
    KeStackAttachProcess(process, &apc);
    // Scan memory
    while (1)
    {
      // Mdl for base addr
      mdl = IoAllocateMdl(base, patternSize, FALSE, FALSE, NULL);
      // Lock pages
      MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
      // Address mapping
      PBYTE mappedBase = (PBYTE)MmMapLockedPagesSpecifyCache(mdl, UserMode, MmNonCached, NULL, FALSE, NormalPagePriority);
      // Set protection levels
      MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
      // Unlock pages
      MmUnmapLockedPages(mappedBase, mdl);
      MmUnlockPages(mdl);
    }
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    LOG_ERROR("Something went wrong\n");
    status = STATUS_FAIL_CHECK;
  }
  // Detach from process
  KeUnstackDetachProcess(&apc);
  // Cleanup
  RtlFreeMemory(asyncBuffer);
  IoFreeMdl(mdl);
  ObDereferenceObject(process);
  return status;
}
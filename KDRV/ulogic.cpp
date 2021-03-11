#include "ulogic.h"
#include "undoc.h"
#include "proc.h"

NTSTATUS GetUserImages(PSYSTEM_PROCESS_INFORMATION images, ULONG size)
{
  NTSTATUS status = STATUS_SUCCESS;
  // Query user images
  status = ZwQuerySystemInformation(SystemProcessInformation, images, size, NULL);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("ZwQuerySystemInformation\n");
    return status;
  }
  __try
  {
    for (ULONG i = 0; i < size; ++i)
      LOG_INFO("%p %ws\n", (PVOID)0, images[i].ImageName.Buffer);
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {

  }
  return status;
}
NTSTATUS GetUserImageBase(ULONG pid, PWCHAR moduleName, PVOID& imageBase)
{
  UNREFERENCED_PARAMETER(moduleName);
  NTSTATUS status = STATUS_SUCCESS;
  // Find process
  PEPROCESS process = NULL;
  status = PsLookupProcessByProcessId((HANDLE)pid, &process);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("PsLookupProcessByProcessId\n");
    return status;
  }
  // Try attach to target process
  KAPC_STATE apc;
  __try
  {
    KeStackAttachProcess(process, &apc);
    // Find base address
    //imageBase = PsGetProcessSectionBaseAddress(process);
    //if (imageBase)
    //{

    // Find PEB struct
    PPEB64 peb64 = (PPEB64)PsGetProcessPeb(process);
    if (peb64)
    {
      // Obtain data table entry
      PLDR_DATA_TABLE_ENTRY modules = GetMainModuleDataTableEntry(peb64);

      imageBase = modules->DllBase;

      //while (modules->InLoadOrderLinks.Flink)
      //{
      //  LOG_INFO("%p %ws\n", modules->DllBase, modules->FullDllName.Buffer);
      //
      //  if (wcscmp(moduleName, modules->BaseDllName.Buffer) == 0)
      //  {
      //    imageBase = modules->DllBase;
      //    break;
      //  }
      //
      //  modules = (PLDR_DATA_TABLE_ENTRY)modules->InLoadOrderLinks.Flink;
      //}

    }

    //}
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    LOG_ERROR("Something went wrong\n");
    status = STATUS_FAIL_CHECK;
  }
  // Compare pointer and status
  if (!imageBase)
    status = STATUS_INVALID_ADDRESS;
  // Cleanup
  KeUnstackDetachProcess(&apc);
  ObDereferenceObject(process);
  return status;
}

NTSTATUS TryReadUserMemory(ULONG pid, PVOID base, PUCHAR buffer, ULONG bufferSize)
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
    LOG_ERROR("IoAllocateMdl\n");
    return STATUS_ACCESS_VIOLATION;
  }
  KAPC_STATE apc;
  __try
  {
    // Attach to process
    KeStackAttachProcess(process, &apc);
    LOG_INFO("mdl created\n");
    LOG_INFO("mdl start virtual base %p\n", mdl->StartVa);
    LOG_INFO("mdl mapped system virtual base %p\n", mdl->MappedSystemVa);
    // Lock memory pages
    MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    LOG_INFO("mdl locked pages\n");
    PVOID mappedBase = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    LOG_INFO("mappedBase %p\n", mappedBase);
    MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
    LOG_INFO("mdl page protection read/write set\n");
    // Read memory
    if (mappedBase)
    {
      LOG_INFO("Copy from %p to %p\n", mappedBase, buffer);
      RtlCopyMemory(buffer, mappedBase, bufferSize);
    }
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
  KeUnstackDetachProcess(&apc);
  IoFreeMdl(mdl);
  ObDereferenceObject(process);
  return status;
}
NTSTATUS TryWriteUserMemory(ULONG pid, PVOID base, PUCHAR buffer, ULONG bufferSize)
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
    LOG_ERROR("IoAllocateMdl\n");
    return STATUS_ACCESS_VIOLATION;
  }
  KAPC_STATE apc;
  __try
  {
    // Attach to process
    KeStackAttachProcess(process, &apc);
    // Lock memory pages
    MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    PVOID mappedBase = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
    // Write memory
    if (mappedBase)
    {
      LOG_INFO("Copy from %p to %p\n", buffer, mappedBase);
      RtlCopyMemory(mappedBase, buffer, bufferSize);
    }
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
  KeUnstackDetachProcess(&apc);
  IoFreeMdl(mdl);
  ObDereferenceObject(process);
  return status;
}
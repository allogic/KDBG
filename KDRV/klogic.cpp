#include "klogic.h"
#include "undoc.h"

NTSTATUS DumpKernelImages()
{
  NTSTATUS status = STATUS_SUCCESS;
  // Optain memory for image module infos
  PRTL_PROCESS_MODULES moduleInfo = (PRTL_PROCESS_MODULES)RtlAllocateMemory(TRUE, sizeof(RTL_PROCESS_MODULES) * 1024 * 1024);
  if (!moduleInfo)
  {
    LOG_ERROR("RtlAllocateMemory\n");
    return STATUS_INVALID_ADDRESS;
  }
  // Query image module infos - SystemModuleInformation(11)
  status = ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, moduleInfo, 1024 * 1024, NULL);
  if (!NT_SUCCESS(status))
  {
    RtlFreeMemory(moduleInfo);
    LOG_ERROR("ZwQuerySystemInformation\n");
    return status;
  }
  // Print image
  for (SIZE_T i = 0; i < moduleInfo->NumberOfModules; ++i)
    LOG_INFO("%p %s\n", moduleInfo->Modules[i].ImageBase, moduleInfo->Modules[i].FullPathName);
  // Cleanup
  RtlFreeMemory(moduleInfo);
  return status;
}
NTSTATUS GetKernelImageBase(PCHAR imageName, PPVOID imageBase, PULONG imageSize)
{
  NTSTATUS status = STATUS_SUCCESS;
  // Optain memory for image module infos
  PRTL_PROCESS_MODULES moduleInfo = (PRTL_PROCESS_MODULES)RtlAllocateMemory(TRUE, sizeof(RTL_PROCESS_MODULES) * 1024 * 1024);
  if (!moduleInfo)
  {
    LOG_ERROR("RtlAllocateMemory\n");
    return STATUS_INVALID_ADDRESS;
  }
  // Query image module infos - SystemModuleInformation(11)
  status = ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, moduleInfo, 1024 * 1024, NULL);
  if (!NT_SUCCESS(status))
  {
    RtlFreeMemory(moduleInfo);
    LOG_ERROR("ZwQuerySystemInformation\n");
    return status;
  }
  // Find image
  for (SIZE_T i = 0; i < moduleInfo->NumberOfModules; ++i)
    if (strcmp(imageName, (PCHAR)(moduleInfo->Modules[i].FullPathName + moduleInfo->Modules[i].OffsetToFileName)) == 0)
    {
      *imageBase = moduleInfo->Modules[i].ImageBase;
      if (imageSize)
        *imageSize = moduleInfo->Modules[i].ImageSize;
      break;
    }
  // Cleanup
  RtlFreeMemory(moduleInfo);
  return status;
}

NTSTATUS TryReadKernelMemory(PVOID base, PUCHAR buffer, ULONG bufferSize)
{
  NTSTATUS status = STATUS_SUCCESS;
  PMDL mdl = IoAllocateMdl(base, bufferSize, FALSE, FALSE, NULL);
  if (!mdl)
  {
    LOG_ERROR("IoAllocateMdl\n");
    return STATUS_ACCESS_VIOLATION;
  }
  __try
  {
    MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    LOG_INFO("Pages locked\n");
    LOG_INFO("Base %p\n", base);
    LOG_INFO("Mdl %p\n", mdl->MappedSystemVa);

    PVOID mappedBase = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    LOG_INFO("Mapping successfull %p\n", mappedBase);
    
    MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
    LOG_INFO("Mdl proteced\n");

    if (mappedBase)
    {
      RtlCopyMemory(buffer, mappedBase, bufferSize);
      LOG_INFO("Copy from %p to %p\n", mappedBase, buffer);
    }

    MmUnmapLockedPages(mappedBase, mdl);
    MmUnlockPages(mdl);

    LOG_INFO("Pages unlocked\n");
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    LOG_ERROR("Something went wrong\n");
    status = STATUS_FAIL_CHECK;
  }
  IoFreeMdl(mdl);
  return status;
}
NTSTATUS TryWriteKernelMemory(PVOID base, PUCHAR buffer, ULONG bufferSize)
{
  NTSTATUS status = STATUS_SUCCESS;
  PMDL mdl = IoAllocateMdl(base, bufferSize, FALSE, FALSE, NULL);
  if (!mdl)
  {
    LOG_ERROR("IoAllocateMdl\n");
    return STATUS_ACCESS_VIOLATION;
  }
  __try
  {
    MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    LOG_INFO("Pages locked\n");
    LOG_INFO("Base %p\n", base);
    LOG_INFO("Mdl %p\n", mdl->MappedSystemVa);

    PVOID mappedBase = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    LOG_INFO("Mapping successfull %p\n", mappedBase);

    MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
    LOG_INFO("Mdl proteced\n");

    if (mappedBase)
    {
      RtlCopyMemory(mappedBase, buffer, bufferSize);
      LOG_INFO("Copy from %p to %p\n", buffer, mappedBase);
    }

    MmUnmapLockedPages(mappedBase, mdl);
    MmUnlockPages(mdl);

    LOG_INFO("Pages unlocked\n");
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    LOG_ERROR("Something went wrong\n");
    status = STATUS_FAIL_CHECK;
  }
  IoFreeMdl(mdl);
  return status;
}
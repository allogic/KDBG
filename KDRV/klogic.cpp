#include "klogic.h"
#include "undoc.h"

NTSTATUS GetKernelImages(PRTL_PROCESS_MODULES images, ULONG size)
{
  NTSTATUS status = STATUS_SUCCESS;
  // Query kernel images
  status = ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, images, size, NULL);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("ZwQuerySystemInformation\n");
    return status;
  }
  __try
  {
    for (ULONG i = 0; i < images[0].NumberOfModules; ++i)
      LOG_INFO("%p %s\n", images[0].Modules[i].ImageBase, images[0].Modules[i].FullPathName);
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {

  }
  return status;
}
NTSTATUS GetKernelImageBase(PCHAR imageName, PVOID& imageBase)
{
  NTSTATUS status = STATUS_SUCCESS;
  // Optain memory for image module infos
  PRTL_PROCESS_MODULES images = (PRTL_PROCESS_MODULES)RtlAllocateMemory(TRUE, sizeof(RTL_PROCESS_MODULES) * 1024 * 1024);
  if (!images)
  {
    LOG_ERROR("RtlAllocateMemory\n");
    return STATUS_INVALID_ADDRESS;
  }
  // Query image module infos - SystemModuleInformation(11)
  status = ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, images, 1024 * 1024, NULL);
  if (!NT_SUCCESS(status))
  {
    RtlFreeMemory(images);
    LOG_ERROR("ZwQuerySystemInformation\n");
    return status;
  }
  // Find image
  for (SIZE_T i = 0; i < images[0].NumberOfModules; ++i)
    if (strcmp(imageName, (PCHAR)(images[0].Modules[i].FullPathName + images[0].Modules[i].OffsetToFileName)) == 0)
    {
      imageBase = images[0].Modules[i].ImageBase;
      break;
    }
  // Cleanup
  RtlFreeMemory(images);
  return status;
}

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
#include "proc.h"

NTSTATUS GetUserImages(PSYSTEM_PROCESS_INFORMATION images, ULONG size)
{
  NTSTATUS status = STATUS_SUCCESS;
  // Query user images
  ULONG returnSize = 0;
  status = ZwQuerySystemInformation(SystemProcessInformation, images, sizeof(SYSTEM_PROCESS_INFORMATION) * size, &returnSize);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("ZwQuerySystemInformation %X\n", status);
    return status;
  }
  returnSize /= sizeof(SYSTEM_PROCESS_INFORMATION);
  // Normalize and print images
  LOG_INFO("Requested %u images\n", size);
  LOG_INFO("Received %u images\n", returnSize);
  for (ULONG i = 0; i < returnSize; ++i)
  {
    LOG_INFO("Pid: %u Name: %wZ\n", *(PULONG)images[i].UniqueProcessId, &images[i].ImageName);
  }
  return status;
}
NTSTATUS GetUserImageModules(ULONG pid, PRTL_PROCESS_MODULES modules, ULONG size)
{
  UNREFERENCED_PARAMETER(pid);
  NTSTATUS status = STATUS_SUCCESS;
  // Query user images
  ULONG returnSize = 0;
  status = ZwQuerySystemInformation(SystemModuleInformation, modules, sizeof(RTL_PROCESS_MODULES) * size, &returnSize);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("ZwQuerySystemInformation %X\n", status);
    return status;
  }
  returnSize /= sizeof(RTL_PROCESS_MODULES);
  // Normalize and print modules
  LOG_INFO("Requested %u modules\n", size);
  LOG_INFO("Received %u modules\n", returnSize);
  for (ULONG i = 0; i < returnSize; ++i)
  {
    LOG_INFO("Number of modules for module: %u\n", modules[i].NumberOfModules);
    LOG_INFO("Name: %s BaseAddress: %p\n", (PCHAR)modules[i].Modules[0].FullPathName, modules[i].Modules[0].ImageBase);
  }
  return status;
}
NTSTATUS GetUserImageThreads(ULONG pid, PSYSTEM_THREAD_INFORMATION threads, ULONG size)
{
  UNREFERENCED_PARAMETER(pid);
  NTSTATUS status = STATUS_SUCCESS;
  // Query user images
  ULONG returnSize = 0;
  status = ZwQuerySystemInformation(SystemProcessInformation, threads, sizeof(SYSTEM_THREAD_INFORMATION) * size, &returnSize);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("ZwQuerySystemInformation %X\n", status);
    return status;
  }
  returnSize /= sizeof(SYSTEM_THREAD_INFORMATION);
  // Normalize and print threads
  LOG_INFO("Requested %u threads\n", size);
  LOG_INFO("Received %u threads\n", returnSize);
  for (ULONG i = 0; i < returnSize; ++i)
  {
    LOG_INFO("Pid: %u Tid: %u BaseAddress: %p\n", *(PULONG)threads[i].ClientId.UniqueProcess, *(PULONG)threads[i].ClientId.UniqueThread, threads[i].StartAddress);
  }
  return status;
}
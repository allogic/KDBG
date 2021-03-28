#include "proc.h"

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
      LOG_INFO("%p %wZ\n", (PVOID)0, &images[i].ImageName);
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
    // Find PEB struct
    PPEB64 peb64 = (PPEB64)PsGetProcessPeb(process);
    if (peb64)
    {
      // Obtain data table entry
      PLDR_DATA_TABLE_ENTRY modules = GetMainModuleDataTableEntry(peb64);
      // Temporarly let the first image to be the target
      imageBase = modules->DllBase;
      // Traverse the list header of the module linked list
      PLDR_DATA_TABLE_ENTRY module = NULL;
      PLIST_ENTRY moduleList = modules->InLoadOrderLinks.Flink;
      PLIST_ENTRY moduleEntry = moduleList->Flink;
      while (moduleEntry != moduleList)
      {
        module = CONTAINING_RECORD(moduleEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (&module->BaseDllName.Buffer != 0)
        {
          //LOG_INFO("%wZ\n", &module->BaseDllName);
          //UNICODE_STRING dllName;
          //RtlInitUnicodeString(&dllName, moduleName);
          //if (RtlCompareUnicodeString(&dllName, &module->BaseDllName, TRUE) == 0)
          //{
          //  LOG_INFO("Target module found %wZ\n", &module->BaseDllName);
          //  imageBase = module->DllBase;
          //}
        }
        // Point to the next linked list
        moduleEntry = moduleEntry->Flink;
      }
    }
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

PLDR_DATA_TABLE_ENTRY GetMainModuleDataTableEntry(PPEB64 peb)
{
  if (SanitizeUserPointer(peb, sizeof(PEB64)))
  {
    if (peb->Ldr)
    {
      if (SanitizeUserPointer(peb->Ldr, sizeof(PEB_LDR_DATA)))
      {
        if (!peb->Ldr->Initialized)
        {
          int initLoadCount = 0;

          while (!peb->Ldr->Initialized && initLoadCount++ < 4)
          {
            DriverSleep(250);
          }
        }

        if (peb->Ldr->Initialized)
        {
          return CONTAINING_RECORD(peb->Ldr->InLoadOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        }
      }
    }
  }
  return NULL;
}
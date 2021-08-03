#include "process.h"
#include "undoc.h"

NTSTATUS
KmGetProcessImageBase(
  ULONG pid,
  PWCHAR imageName,
  PVOID& base)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  PEPROCESS process = NULL;
  KAPC_STATE apc;
  status = PsLookupProcessByProcessId((HANDLE)pid, &process);
  if (NT_SUCCESS(status))
  {
    status = STATUS_UNSUCCESSFUL;
    KeStackAttachProcess(process, &apc);
    __try
    {
      PPEB64 peb = (PPEB64)PsGetProcessPeb(process);
      if (peb)
      {
        PVOID imageBase = peb->ImageBaseAddress;
        PLDR_DATA_TABLE_ENTRY modules = CONTAINING_RECORD(peb->Ldr->InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);;
        PLDR_DATA_TABLE_ENTRY module = NULL;
        PLIST_ENTRY moduleHead = modules->InMemoryOrderLinks.Flink;
        PLIST_ENTRY moduleEntry = moduleHead->Flink;
        while (moduleEntry != moduleHead)
        {
          module = CONTAINING_RECORD(moduleEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
          if (module && module->DllBase)
          {
            if (_wcsicmp(imageName, module->BaseDllName.Buffer) == 0)
            {
              break;
            }
          }
          moduleEntry = moduleEntry->Flink;
        }
        base = module->DllBase;
        status = STATUS_SUCCESS;
        KM_LOG_INFO("Selected module %ls\n", module->BaseDllName.Buffer);
      }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
      KM_LOG_ERROR("Something went wrong!\n");
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(process);
  }
  return status;
}

NTSTATUS
KmGetKernelImageBase(
  PCHAR imageName,
  PVOID& imageBase)
{
  NTSTATUS status = STATUS_SUCCESS;
  PRTL_PROCESS_MODULES images = (PRTL_PROCESS_MODULES)KmAllocateMemory(TRUE, sizeof(RTL_PROCESS_MODULES) * 1024 * 1024);
  if (images)
  {
    status = ZwQuerySystemInformation(SystemModuleInformation, images, sizeof(RTL_PROCESS_MODULES) * 1024 * 1024, NULL);
    if (NT_SUCCESS(status))
    {
      for (ULONG i = 0; i < images[0].NumberOfModules; ++i)
      {
        if (_stricmp(imageName, (PCHAR)(images[0].Modules[i].FullPathName + images[0].Modules[i].OffsetToFileName)) == 0)
        {
          imageBase = images[0].Modules[i].ImageBase;
          KM_LOG_INFO("Selected module %s\n", (PCHAR)(images[0].Modules[i].FullPathName + images[0].Modules[i].OffsetToFileName));
          break;
        }
      }
    }
    KmFreeMemory(images);
  }
  return status;
}
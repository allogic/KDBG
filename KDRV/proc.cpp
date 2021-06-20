#include "proc.h"

VOID GetKernelModules(PKDRV_REQ_DUMP_MODULES request, BOOL verbose)
{
  ULONG bytes = 0;
  ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
  PRTL_PROCESS_MODULES buffer = (PRTL_PROCESS_MODULES)RtlAllocateMemory(TRUE, bytes);
  ZwQuerySystemInformation(SystemModuleInformation, buffer, bytes, &bytes);
  request->Size = bytes / sizeof(RTL_PROCESS_MODULES);
  RtlCopyMemory(request->Buffer, buffer, bytes);
  PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)buffer;
  PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
  if (verbose)
  {
    for (ULONG i = 0; i < modules->NumberOfModules; ++i)
    {
      LOG_INFO("Module: %s\n", (PCHAR)(module[i].FullPathName + module[i].OffsetToFileName));
      LOG_INFO("Size: %u\n", module[i].ImageSize);
    }
  }
  RtlFreeMemory(buffer);
}
VOID GetUserModules(PEPROCESS process, PKDRV_REQ_DUMP_MODULES request, BOOL verbose)
{
  KAPC_STATE apc;
  KeStackAttachProcess(process, &apc);
  PPEB64 peb64 = (PPEB64)PsGetProcessPeb(process);
  PLDR_DATA_TABLE_ENTRY ldrTable = CONTAINING_RECORD(peb64->Ldr->InLoadOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
  PLDR_DATA_TABLE_ENTRY module = NULL;
  PLIST_ENTRY entry = NULL;
  PLIST_ENTRY head = &ldrTable->InMemoryOrderLinks;
  ULONG moduleAcc = 0;
  ULONG byteOffset = 0;
  entry = head->Flink;
  while (entry != head)
  {
    module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    //CopyUserMemory((PVOID)((ULONG_PTR)request->Buffer + byteOffset), module, sizeof(LDR_DATA_TABLE_ENTRY));
    moduleAcc++;
    byteOffset += sizeof(LDR_DATA_TABLE_ENTRY);
    if (verbose)
    {
      LOG_INFO("Module: %wZ\n", &module->BaseDllName);
      LOG_INFO("Size: %u\n", module->SizeOfImage);
    }
    entry = entry->Flink;
  }
  // source 00000206DB0D06E0
  // dest   0000015731E604D0
  request->Size = moduleAcc;
  KeUnstackDetachProcess(&apc);
}

PVOID GetKernelModuleBase(PCHAR moduleName)
{
  PVOID moduleBase = 0;
  ULONG bytes = 0;
  ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
  PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)RtlAllocateMemory(TRUE, bytes);
  ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);
  PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
  for (ULONG i = 0; i < modules->NumberOfModules; ++i)
  {
    if (strcmp((PCHAR)(module[i].FullPathName + module[i].OffsetToFileName), moduleName) == 0)
    {
      moduleBase = module[i].ImageBase;
      break;
    }
  }
  if (modules)
  {
    RtlFreeMemory(modules);
  }
  return moduleName;
}
PVOID GetUserModuleBase(PEPROCESS process, PWCHAR moduleName)
{
  PVOID moduleBase = NULL;
  KAPC_STATE apc;
  KeStackAttachProcess(process, &apc);
  PPEB64 peb64 = (PPEB64)PsGetProcessPeb(process);
  PLDR_DATA_TABLE_ENTRY modules = CONTAINING_RECORD(peb64->Ldr->InLoadOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
  PLDR_DATA_TABLE_ENTRY module = NULL;
  PLIST_ENTRY moduleList = modules->InLoadOrderLinks.Flink;
  PLIST_ENTRY moduleEntry = moduleList->Flink;
  UNICODE_STRING dllName;
  while (moduleEntry != moduleList)
  {
    module = CONTAINING_RECORD(moduleEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    RtlInitUnicodeString(&dllName, moduleName);
    if (RtlCompareUnicodeString(&dllName, &module->BaseDllName, TRUE) == 0)
    {
      moduleBase = module->DllBase;
      break;
    }
    moduleEntry = moduleEntry->Flink;
  }
  KeUnstackDetachProcess(&apc);
  return moduleBase;
}
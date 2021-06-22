#include "proc.h"

VOID GetKernelModules(PKDRV_REQ_DUMP_MODULES request, BOOL verbose)
{
  ULONG bytes = 0;
  ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
  PRTL_PROCESS_MODULES buffer = (PRTL_PROCESS_MODULES)RtlAllocateMemory(TRUE, bytes);
  ZwQuerySystemInformation(SystemModuleInformation, buffer, bytes, &bytes);
  PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)buffer;
  PRTL_PROCESS_MODULE_INFORMATION moduleInfo = modules->Modules;
  ULONG size = bytes / sizeof(RTL_PROCESS_MODULES);
  for (ULONG i = 0; i < size; ++i)
  {
    if (verbose)
    {
      LOG_INFO("Name: %p\n", moduleInfo[i].ImageBase);
      LOG_INFO("Name: %s\n", (PCHAR)(moduleInfo[i].FullPathName + moduleInfo[i].OffsetToFileName));
      LOG_INFO("Size: %u\n", moduleInfo[i].ImageSize);
    }
    request->Modules[i].Base = moduleInfo[i].ImageBase;
    strcpy(request->Modules[i].Name, (PCHAR)(moduleInfo[i].FullPathName + moduleInfo[i].OffsetToFileName));
  }
  request->Size = size;
  RtlFreeMemory(buffer);
}
VOID GetUserThreads(PKDRV_REQ_DUMP_THREADS request, BOOL verbose)
{
  ULONG bytes = 0;
  ZwQuerySystemInformation(SystemProcessInformation, 0, bytes, &bytes);
  PSYSTEM_THREAD_INFORMATION buffer = (PSYSTEM_THREAD_INFORMATION)RtlAllocateMemory(TRUE, bytes);
  ZwQuerySystemInformation(SystemProcessInformation, buffer, bytes, &bytes);
  ULONG size = bytes / sizeof(SYSTEM_THREAD_INFORMATION);
  for (ULONG i = 0; i < size; ++i)
  {
    if (verbose)
    {
      LOG_INFO("Pid: %u\n", *(PULONG)(buffer[i].ClientId.UniqueProcess));
      LOG_INFO("Tid: %u\n", *(PULONG)(buffer[i].ClientId.UniqueThread));
      LOG_INFO("Start: %p\n", buffer[i].StartAddress);
      LOG_INFO("State: %u\n", buffer[i].ThreadState);
    }
    request->Threads[i].Pid = *(PULONG)(buffer[i].ClientId.UniqueProcess);
    request->Threads[i].Tid = *(PULONG)(buffer[i].ClientId.UniqueThread);
    request->Threads[i].Start = buffer[i].StartAddress;
    request->Threads[i].State = buffer[i].ThreadState;
  }
  request->Size = size;
  RtlFreeMemory(buffer);
}

VOID GetUserModulesSave(PEPROCESS process, PKDRV_REQ_DUMP_MODULES request, BOOL verbose)
{
  PPEB64 peb64 = (PPEB64)PsGetProcessPeb(process);
  PLDR_DATA_TABLE_ENTRY ldrTable = CONTAINING_RECORD(peb64->Ldr->InLoadOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
  PLDR_DATA_TABLE_ENTRY ldr = NULL;
  PLIST_ENTRY entry = NULL;
  PLIST_ENTRY head = &ldrTable->InMemoryOrderLinks;
  ULONG moduleAcc = 0;
  entry = head->Flink;
  while (entry != head)
  {
    ldr = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    if (verbose)
    {
      LOG_INFO("Base: %p\n", ldr->DllBase);
      LOG_INFO("Name: %wZ\n", &ldr->BaseDllName);
      LOG_INFO("Size: %u\n", ldr->SizeOfImage);
    }
    request->Modules[moduleAcc].Base = ldr->DllBase;
    wcscpy(request->Modules[moduleAcc].WName, ldr->BaseDllName.Buffer);
    request->Modules[moduleAcc].Size = ldr->SizeOfImage;
    ++moduleAcc;
    entry = entry->Flink;
  }
  request->Size = moduleAcc;
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
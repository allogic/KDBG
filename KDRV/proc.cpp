#include "proc.h"

VOID GetKernelImages(PKDRV_REQ_DUMP_KRNL_IMAGES request, BOOL verbose)
{
  ULONG bytes = 0;
  ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
  PRTL_PROCESS_MODULES buffer = (PRTL_PROCESS_MODULES)RtlAllocateMemory(TRUE, bytes);
  ZwQuerySystemInformation(SystemModuleInformation, buffer, bytes, &bytes);
  PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)buffer;
  PRTL_PROCESS_MODULE_INFORMATION moduleInfo = modules->Modules;
  ULONG moduleCount = bytes / sizeof(RTL_PROCESS_MODULES);
  for (ULONG i = 0; i < moduleCount; ++i)
  {
    if (verbose)
    {
      LOG_INFO("Base: %p\n", moduleInfo[i].ImageBase);
      LOG_INFO("Name: %s\n", (PCHAR)(moduleInfo[i].FullPathName + moduleInfo[i].OffsetToFileName));
      LOG_INFO("Size: %u\n", moduleInfo[i].ImageSize);
      LOG_INFO("\n");
    }
    request->Modules[i].Base = moduleInfo[i].ImageBase;
    strcpy(request->Modules[i].Name, (PCHAR)(moduleInfo[i].FullPathName + moduleInfo[i].OffsetToFileName));
    request->Modules[i].Size = moduleInfo[i].ImageSize;
  }
  request->ModuleCount = moduleCount;
  RtlFreeMemory(buffer);
}
VOID GetUserProcesses(PKDRV_REQ_DUMP_PROCESSES request, BOOL verbose)
{
  ULONG bytes = 0;
  NTSTATUS status = STATUS_SUCCESS;
  status = ZwQuerySystemInformation(SystemProcessInformation, 0, bytes, &bytes);
  LOG_ERROR_IF_NOT_SUCCESS(status, "ZwQuerySystemInformation %u\n", status);
  LOG_INFO("Got %u bytes\n", bytes);
  LOG_INFO("Required %u bytes\n", sizeof(SYSTEM_PROCESS_INFORMATION) * request->ProcessCount + sizeof(SYSTEM_THREAD_INFORMATION) * request->ThreadCount);
  PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)RtlAllocateMemory(TRUE, max(bytes, sizeof(SYSTEM_PROCESS_INFORMATION) * request->ProcessCount + sizeof(SYSTEM_THREAD_INFORMATION) * request->ThreadCount));
  status = ZwQuerySystemInformation(SystemProcessInformation, processInfo, max(bytes, sizeof(SYSTEM_PROCESS_INFORMATION) * request->ProcessCount + sizeof(SYSTEM_THREAD_INFORMATION) * request->ThreadCount), &bytes);
  LOG_INFO("Received %u bytes\n", bytes);
  LOG_ERROR_IF_NOT_SUCCESS(status, "ZwQuerySystemInformation %u\n", status);
  ULONG processAcc = 0;
  while (1)
  {
    if (verbose)
    {
      //LOG_INFO("Name: %wZ\n", processInfo->ImageName.Buffer);
      LOG_INFO("Pid: %u\n", *(PULONG)processInfo->UniqueProcessId);
      LOG_INFO("Threads: %u\n", processInfo->NumberOfThreads);
    }
    for (ULONG i = 0; i < processInfo->NumberOfThreads; ++i)
    {
      PSYSTEM_THREAD_INFORMATION thread = (PSYSTEM_THREAD_INFORMATION)(((PBYTE)processInfo) + sizeof(SYSTEM_PROCESS_INFORMATION) + sizeof(SYSTEM_THREAD_INFORMATION) * i);
      if (verbose)
      {
        LOG_INFO("\tTid: %u\n", *(PULONG)thread->ClientId.UniqueThread);
        LOG_INFO("\tBase: %p\n", thread->StartAddress);
        LOG_INFO("\n");
      }
      //request->Processes[processAcc].Threads[i].Tid = *(PULONG)thread->ClientId.UniqueThread;
      //request->Processes[processAcc].Threads[i].Base = thread->StartAddress;
      //request->Processes[processAcc].Threads[i].State = thread->ThreadState;
    }
    //request->Processes[processAcc].Pid = *(PULONG)processInfo->UniqueProcessId;
    //wcscpy(request->Processes[processAcc].Name, processInfo->ImageName.Buffer);
    if (!processInfo->NextEntryOffset)
    {
      break;
    }
    processInfo = (PSYSTEM_PROCESS_INFORMATION)(((PBYTE)processInfo) + processInfo->NextEntryOffset);
    processAcc++;
  }
  request->ProcessCount = processAcc;
  RtlFreeMemory(processInfo);
}

/*
VOID GetUserModulesSave(PEPROCESS process, PKDRV_REQ_DUMP_MODULES request, BOOL verbose)
{
  KAPC_STATE apc;
  KeStackAttachProcess(process, &apc);
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
    //request->Modules[moduleAcc].Base = ldr->DllBase;
    //wcscpy(request->Modules[moduleAcc].WName, ldr->BaseDllName.Buffer);
    //request->Modules[moduleAcc].Size = ldr->SizeOfImage;
    ++moduleAcc;
    entry = entry->Flink;
  }
  request->Size = moduleAcc;
  KeUnstackDetachProcess(&apc);
}
*/

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
#include "global.h"
#include "common.h"
#include "ioctrl.h"
#include "krnl.h"
#include "pe.h"
#include "thread.h"
#include "trace.h"
#include "socket.h"

/*
* Global driver state.
*/

ULONG Pid = 0;

MODULE ModulesKernel[KM_MAX_MODULES_KERNEL] = {}; // Buffer is required in order to copy from process memory to kernel memory to process again.
MODULE ModulesProcess[KM_MAX_MODULES_PROCESS] = {}; // Buffer is required in order to copy from process memory to kernel memory to process again.
THREAD ThreadsProcess[KM_MAX_THREADS_PROCESS] = {}; // Buffer is required in order to copy from process memory to kernel memory to process again.

/*
* Process utilities relative to kernel space.
*/

NTSTATUS KmInterlockedMemcpy(PVOID dst, PVOID src, SIZE_T size, KPROCESSOR_MODE mode)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  PMDL mdl = IoAllocateMdl(src, size, FALSE, FALSE, NULL);
  if (mdl)
  {
    MmProbeAndLockPages(mdl, mode, IoReadAccess);
    PVOID mappedSrc = MmMapLockedPagesSpecifyCache(mdl, mode, MmNonCached, NULL, FALSE, HighPagePriority);
    if (mappedSrc)
    {
      status = MmProtectMdlSystemAddress(mdl, PAGE_READONLY);
      if (NT_SUCCESS(status))
      {
        __try
        {
          memcpy(dst, mappedSrc, size);
          status = STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
          KM_LOG_INFO("Something went wrong\n");
        }
      }
      MmUnmapLockedPages(mappedSrc, mdl);
    }
    MmUnlockPages(mdl);
  }
  IoFreeMdl(mdl);
  return status;
}

NTSTATUS KmFetchKernelModules()
{
  return STATUS_UNSUCCESSFUL;
}

NTSTATUS KmFetchProcessModules()
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  PEPROCESS process = NULL;
  KAPC_STATE apc;
  status = PsLookupProcessByProcessId((HANDLE)Pid, &process);
  if (NT_SUCCESS(status))
  {
    status = STATUS_UNSUCCESSFUL;
    KeStackAttachProcess(process, &apc);
    __try
    {
      PPEB64 peb = (PPEB64)PsGetProcessPeb(process);
      if (peb)
      {
        memset(ModulesProcess, 0, sizeof(MODULE) * KM_MAX_MODULES_PROCESS);
        PVOID imageBase = peb->ImageBaseAddress;
        PLDR_DATA_TABLE_ENTRY modules = CONTAINING_RECORD(peb->Ldr->InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);;
        PLDR_DATA_TABLE_ENTRY module = NULL;
        PLIST_ENTRY moduleHead = modules->InMemoryOrderLinks.Flink;
        PLIST_ENTRY moduleEntry = moduleHead->Flink;
        ULONG count = 0;
        while (moduleEntry != moduleHead)
        {
          module = CONTAINING_RECORD(moduleEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
          if (module && module->DllBase)
          {
            KmInterlockedMemcpy(&ModulesProcess[count].Base, &module->DllBase, sizeof(ULONG64), KernelMode);
            KmInterlockedMemcpy(&ModulesProcess[count].Name, module->BaseDllName.Buffer, sizeof(WCHAR) * module->BaseDllName.Length, KernelMode);
            KmInterlockedMemcpy(&ModulesProcess[count].Size, &module->SizeOfImage, sizeof(ULONG), KernelMode);
            count++;
            if (count >= KM_MAX_MODULES_PROCESS)
            {
              break;
            }
          }
          moduleEntry = moduleEntry->Flink;
        }
        KM_LOG_INFO("Fetched modules\n");
        status = STATUS_SUCCESS;
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
NTSTATUS KmFetchProcessThreads()
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  ULONG read = 0;
  PBYTE buffer = (PBYTE)KmAllocateMemory(TRUE, 1024 * 1024);
  status = ZwQuerySystemInformation(SystemProcessInformation, buffer, read, &read);
  ULONG processAcc = 0;
  while (1)
  {
    KM_LOG_INFO("Thread count %u\n", ((PSYSTEM_PROCESS_INFORMATION)buffer)->NumberOfThreads);
    //KM_LOG_INFO("Tid %u Pid %u\n", (ULONG)threads[i].ClientId.UniqueThread, (ULONG)threads[i].ClientId.UniqueProcess);
    //KM_LOG_INFO("Copy from %p to %p\n", &threads[i].ClientId.UniqueThread, &Threads[i].Tid);
    //for (ULONG i = 0; i < processInfo->NumberOfThreads; ++i)
    //{
    //  PSYSTEM_THREAD_INFORMATION thread = (PSYSTEM_THREAD_INFORMATION)(((PBYTE)processInfo) + sizeof(SYSTEM_PROCESS_INFORMATION) + sizeof(SYSTEM_THREAD_INFORMATION) * i);
    //  if (verbose)
    //  {
    //    LOG_INFO("\tTid: %u\n", *(PULONG)thread->ClientId.UniqueThread);
    //    LOG_INFO("\tBase: %p\n", thread->StartAddress);
    //    LOG_INFO("\n");
    //  }
    //  //request->Processes[processAcc].Threads[i].Tid = *(PULONG)thread->ClientId.UniqueThread;
    //  //request->Processes[processAcc].Threads[i].Base = thread->StartAddress;
    //  //request->Processes[processAcc].Threads[i].State = thread->ThreadState;
    //}
    if (!((PSYSTEM_PROCESS_INFORMATION)buffer)->NextEntryOffset)
    {
      KM_LOG_INFO("Fetched threads\n");
      status = STATUS_SUCCESS;
      break;
    }
    buffer += ((PSYSTEM_PROCESS_INFORMATION)buffer)->NextEntryOffset;
    processAcc++;
  }
  KmFreeMemory(buffer);
  return status;
}

NTSTATUS KmGetProcessModules(ULONG pid, SIZE_T size, SIZE_T& count, PVOID buffer)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  PEPROCESS process = NULL;
  KAPC_STATE apc;
  status = PsLookupProcessByProcessId((HANDLE)pid, &process);
  if (NT_SUCCESS(status))
  {
    status = STATUS_UNSUCCESSFUL;
    KeStackAttachProcess(process, &apc);
    KM_LOG_INFO("Attached\n");
    __try
    {
      PPEB64 peb = (PPEB64)PsGetProcessPeb(process);
      if (peb)
      {
        KM_LOG_INFO("Found PEB\n");
        PVOID imageBase = peb->ImageBaseAddress;
        PLDR_DATA_TABLE_ENTRY modules = CONTAINING_RECORD(peb->Ldr->InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);;
        PLDR_DATA_TABLE_ENTRY module = NULL;
        PLIST_ENTRY moduleHead = modules->InMemoryOrderLinks.Flink;
        PLIST_ENTRY moduleEntry = moduleHead->Flink;
        while (moduleEntry != moduleHead)
        {
          module = CONTAINING_RECORD(moduleEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
          KM_LOG_INFO("%ls\n", module->BaseDllName.Buffer);
          if (module && module->DllBase)
          {
            KmInterlockedMemcpy(&((PMODULE)buffer)[count].Base, &module->DllBase, sizeof(ULONG64), UserMode);
            KmInterlockedMemcpy(&((PMODULE)buffer)[count].Size, &module->DllBase, sizeof(SIZE_T), UserMode);
            count++;
            KM_LOG_INFO("%llu copied %ls\n", count, module->BaseDllName.Buffer);
            KM_LOG_INFO("value is %p\n");
            if (count >= size)
            {
              break;
            }
          }
          moduleEntry = moduleEntry->Flink;
        }
        status = STATUS_SUCCESS;
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
NTSTATUS KmGetProcessModuleBase(ULONG pid, PWCHAR name, PVOID& base)
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
            if (_wcsicmp(name, module->BaseDllName.Buffer) == 0)
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

NTSTATUS KmReadVirtualProcessMemory(ULONG pid, PVOID base, SIZE_T size, PVOID buffer)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  PEPROCESS process = NULL;
  KAPC_STATE apc;
  status = PsLookupProcessByProcessId((HANDLE)pid, &process);
  if (NT_SUCCESS(status))
  {
    status = STATUS_UNSUCCESSFUL;
    PBYTE asyncBuffer = (PBYTE)KmAllocateMemory(TRUE, size);
    if (asyncBuffer)
    {
      PMDL mdl = IoAllocateMdl(base, size, FALSE, FALSE, NULL);
      if (mdl)
      {
        KeStackAttachProcess(process, &apc);
        __try
        {
          MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
          PBYTE mappedBuffer = (PBYTE)MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, HighPagePriority);
          if (mappedBuffer)
          {
            status = MmProtectMdlSystemAddress(mdl, PAGE_READONLY);
            if (NT_SUCCESS(status))
            {
              status = STATUS_UNSUCCESSFUL;
              memcpy(asyncBuffer, mappedBuffer, size);
              KM_LOG_INFO("Copy successfull\n");
              status = STATUS_SUCCESS;
            }
            MmUnmapLockedPages(mappedBuffer, mdl);
          }
          MmUnlockPages(mdl);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
          KM_LOG_ERROR("Something went wrong!\n");
          status = STATUS_UNHANDLED_EXCEPTION;
        }
        KeUnstackDetachProcess(&apc);
        IoFreeMdl(mdl);
      }
      memcpy(buffer, asyncBuffer, size);
      KmFreeMemory(asyncBuffer);
    }
    ObDereferenceObject(process);
  }
  return status;
}
NTSTATUS KmWriteVirtualProcessMemory(ULONG pid, PVOID base, SIZE_T size, PVOID buffer)
{
  return STATUS_UNSUCCESSFUL;
}

/*
* Request/Response handlers.
*/

/*
NTSTATUS KmHandleProcessAttachRequest(PREQ_PROCESS_ATTACH req)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  Pid = req->In.Pid;
  KM_LOG_INFO("Attached to process %u\n", Pid);
  status = STATUS_SUCCESS;
  return status;
}
NTSTATUS KmHandleProcessModulesRequest(PREQ_PROCESS_MODULES req)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  if (Pid)
  {
    status = KmFetchProcessModules();
    if (NT_SUCCESS(status))
    {
      memcpy(req->Out.Buffer, ModulesProcess, sizeof(MODULE) * KM_MAX_MODULES_PROCESS);
    }
  }
  return status;
}
NTSTATUS KmHandleProcessThreadsRequest(PREQ_PROCESS_THREADS req)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  if (Pid)
  {
    status = KmFetchProcessThreads();
    if (NT_SUCCESS(status))
    {
      memcpy(req->Out.Buffer, ThreadsProcess, sizeof(THREAD) * KM_MAX_THREADS_PROCESS);
    }
  }
  return status;
}
*/

NTSTATUS KmMemoryReadRequest(PKSOCKET socket, PREAD_MEMORY_PROCESS request)
{
  NTSTATUS status = STATUS_SUCCESS;
  //PVOID base = NULL;
  //PVOID buffer = KmAllocateMemory(TRUE, request->Size);
  //status = KmGetProcessModuleBase(request->Pid, request->ImageName, base);
  //if (NT_SUCCESS(status))
  //{
  //  status = KmReadVirtualProcessMemory(request->Pid, (PVOID)((PBYTE)base + request->Offset), request->Size, buffer);
  //  if (NT_SUCCESS(status))
  //  {
  //    ULONG size = request->Size;
  //    status = KsSend(socket, buffer, &size, WSK_FLAG_WAITALL);
  //    if (NT_SUCCESS(status))
  //    {
  //
  //    }
  //  }
  //}
  //KmFreeMemory(buffer);
  return status;
}
NTSTATUS KmMemoryWriteRequest(PKSOCKET socket, PWRITE_MEMORY_PROCESS request)
{
  NTSTATUS status = STATUS_SUCCESS;
  //PVOID base = NULL;
  //PVOID buffer = KmAllocateMemory(TRUE, request->Size);
  //status = KmGetProcessModuleBase(request->Pid, request->ImageName, base);
  //if (NT_SUCCESS(status))
  //{
  //  status = KmReadVirtualProcessMemory(request->Pid, (PVOID)((PBYTE)base + request->Offset), request->Size, buffer);
  //  if (NT_SUCCESS(status))
  //  {
  //    ULONG size = request->Size;
  //    status = KsSend(socket, buffer, &size, WSK_FLAG_WAITALL);
  //    if (NT_SUCCESS(status))
  //    {
  //
  //    }
  //  }
  //}
  //KmFreeMemory(buffer);
  return status;
}

/*
* Communication socket.
*/

#define KM_MAX_TCP_SESSIONS 128

typedef struct _TCP_CONTEXT
{
  PKSOCKET Socket = NULL;
  HANDLE Thread = NULL;
} TCP_CONTEXT, * PTCP_CONTEXT;

TCP_CONTEXT Server = {};
TCP_CONTEXT Clients[KM_MAX_TCP_SESSIONS] = {};

VOID KmSessionThread(PVOID context)
{
  PTCP_CONTEXT tcpContext = (PTCP_CONTEXT)context;
  KM_LOG_INFO("Session thread begin\n");
  NTSTATUS status = STATUS_SUCCESS;
  ULONG size = 0;
  CHAR ctrl = 0;
  while (TRUE)
  {
    status = STATUS_UNSUCCESSFUL;
    size = sizeof(CHAR);
    ctrl = 0;
    status = KsRecv(tcpContext->Socket, &ctrl, &size, WSK_FLAG_WAITALL);
    if (NT_SUCCESS(status))
    {
      switch (ctrl)
      {
        case KM_READ_MEMORY_PROCESS:
        {
          size = sizeof(READ_MEMORY_PROCESS);
          READ_MEMORY_PROCESS request = {};
          status = KsRecv(tcpContext->Socket, &request, &size, WSK_FLAG_WAITALL);
          if (NT_SUCCESS(status))
          {
            KM_LOG_INFO("Received memory read request\n");
            KM_LOG_INFO("Pid %u\n", request.Pid);
            KM_LOG_INFO("ImageName %ls\n", request.ImageName);
            KM_LOG_INFO("Offset %u\n", request.Offset);
            KM_LOG_INFO("Size %u\n", request.Size);
            status = KmMemoryReadRequest(tcpContext->Socket, &request);
          }
          break;
        }
        case KM_WRITE_MEMORY_PROCESS:
        {
          size = sizeof(WRITE_MEMORY_PROCESS);
          WRITE_MEMORY_PROCESS request = {};
          status = KsRecv(tcpContext->Socket, &request, &size, WSK_FLAG_WAITALL);
          if (NT_SUCCESS(status))
          {
            KM_LOG_INFO("Received memory write request\n");
            KM_LOG_INFO("Pid %u\n", request.Pid);
            KM_LOG_INFO("ImageName %ls\n", request.ImageName);
            KM_LOG_INFO("Offset %u\n", request.Offset);
            KM_LOG_INFO("Size %u\n", request.Size);
            status = KmMemoryWriteRequest(tcpContext->Socket, &request);
          }
          break;
        }
      }
      if (NT_SUCCESS(status))
      {
        KM_LOG_INFO("Handshake successfull\n");
      }
    }
  }
  KsCloseSocket(tcpContext->Socket);
  PsTerminateSystemThread(status);
}

/*
* Entry point.
*/

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING regPath)
{
  UNREFERENCED_PARAMETER(regPath);
  NTSTATUS status = STATUS_SUCCESS;
  status = KsInitialize();
  if (NT_SUCCESS(status))
  {
    status = KsCreateListenSocket(&Server.Socket, AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (NT_SUCCESS(status))
    {
      SOCKADDR_IN hints = {};
      hints.sin_family = AF_INET;
      hints.sin_addr.s_addr = INADDR_ANY;
      hints.sin_port = RtlUshortByteSwap(9095);
      status = KsBind(Server.Socket, (PSOCKADDR)&hints);
      if (NT_SUCCESS(status))
      {
        ULONG clientId = 0;
        while (TRUE)
        {
          KM_LOG_INFO("Listening..\n");
          status = KsAccept(Server.Socket, &Clients[clientId].Socket, NULL, (PSOCKADDR)&hints);
          if (NT_SUCCESS(status))
          {
            status = PsCreateSystemThread(&Clients[clientId].Thread, STANDARD_RIGHTS_ALL, NULL, NULL, NULL, KmSessionThread, &Clients[clientId]);
            if (NT_SUCCESS(status))
            {
              clientId++;
            }
            else
            {
              KsCloseSocket(Clients[clientId].Socket);
            }
          }
        }
      }
    }
    KsDestroy();
  }
  return status;
}
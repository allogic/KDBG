#include "global.h"
#include "common.h"
#include "ioctrl.h"
#include "device.h"
#include "undoc.h"
#include "pe.h"
#include "memory.h"
#include "process.h"
#include "thread.h"
#include "trace.h"

/*
* Global driver state.
*/

MODULE ModulesKernel[KM_MAX_MODULES_KERNEL] = {}; // Buffer is required in order to copy from process memory to kernel memory to process again.
MODULE ModulesProcess[KM_MAX_MODULES_PROCESS] = {}; // Buffer is required in order to copy from process memory to kernel memory to process again.
THREAD ThreadsProcess[KM_MAX_THREADS_PROCESS] = {}; // Buffer is required in order to copy from process memory to kernel memory to process again.

/*
* Process utilities relative to kernel space.
*/

NTSTATUS KmFetchProcessModules(ULONG pid)
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

/*
* Request/Response handlers.
*/

NTSTATUS KmHandleReadMemoryProcess(PREAD_MEMORY_PROCESS request, PVOID buffer)
{
  NTSTATUS status = STATUS_SUCCESS;
  PVOID base = NULL;
  status = KmGetProcessImageBase(request->Pid, request->ImageName, base);
  if (NT_SUCCESS(status))
  {
    status = KmReadMemoryProcess(request->Pid, (PVOID)((PBYTE)base + request->Offset), request->Size, buffer);
    if (NT_SUCCESS(status))
    {
      KM_LOG_INFO("Read successfull\n");
    }
  }
  return status;
}
NTSTATUS KmHandleReadMemoryKernel(PREAD_MEMORY_KERNEL request, PVOID buffer)
{
  NTSTATUS status = STATUS_SUCCESS;
  PVOID base = NULL;
  status = KmGetKernelImageBase(request->ImageName, base);
  if (NT_SUCCESS(status))
  {
    status = KmReadMemoryKernel((PVOID)((PBYTE)base + request->Offset), request->Size, buffer);
    if (NT_SUCCESS(status))
    {
      KM_LOG_INFO("Read successfull\n");
    }
  }
  return status;
}

/*
* I/O callbacks.
*/

NTSTATUS OnIrpDflt(PDEVICE_OBJECT device, PIRP irp)
{
  UNREFERENCED_PARAMETER(device);
  irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
  irp->IoStatus.Information = 0;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return irp->IoStatus.Status;
}
NTSTATUS OnIrpCreate(PDEVICE_OBJECT device, PIRP irp)
{
  UNREFERENCED_PARAMETER(device);
  irp->IoStatus.Status = STATUS_SUCCESS;
  irp->IoStatus.Information = 0;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return irp->IoStatus.Status;
}
NTSTATUS OnIrpCtrl(PDEVICE_OBJECT device, PIRP irp)
{
  UNREFERENCED_PARAMETER(device);
  PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
  switch (stack->Parameters.DeviceIoControl.IoControlCode)
  {
    case KM_READ_MEMORY_PROCESS:
    {
      KM_LOG_INFO("Begin read memory process\n");
      READ_MEMORY_PROCESS request = *(PREAD_MEMORY_PROCESS)irp->AssociatedIrp.SystemBuffer;
      irp->IoStatus.Status = KmHandleReadMemoryProcess(&request, irp->AssociatedIrp.SystemBuffer);
      irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? request.Size : 0;
      KM_LOG_INFO("End read memory process\n");
      break;
    }
    case KM_READ_MEMORY_KERNEL:
    {
      KM_LOG_INFO("Begin read memory kernel\n");
      READ_MEMORY_KERNEL request = *(PREAD_MEMORY_KERNEL)irp->AssociatedIrp.SystemBuffer;
      irp->IoStatus.Status = KmHandleReadMemoryKernel(&request, irp->AssociatedIrp.SystemBuffer);
      irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? request.Size : 0;
      KM_LOG_INFO("End read memory kernel\n");
      break;
    }
  }
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  KM_LOG_INFO("========================================\n");
  return irp->IoStatus.Status;
}
NTSTATUS OnIrpClose(PDEVICE_OBJECT device, PIRP irp)
{
  UNREFERENCED_PARAMETER(device);
  irp->IoStatus.Status = STATUS_SUCCESS;
  irp->IoStatus.Information = 0;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return irp->IoStatus.Status;
}

/*
* I/O communication device.
*/

PDEVICE_OBJECT Device = NULL;

#define KMOD_DEVICE_NAME L"\\Device\\KMOD"
#define KMOD_DEVICE_SYMBOL_NAME L"\\DosDevices\\KMOD"

/*
* Entry point.
*/

VOID DriverUnload(PDRIVER_OBJECT driver)
{
  UNREFERENCED_PARAMETER(driver);
  NTSTATUS status = STATUS_SUCCESS;
  status = DeleteDevice(Device, KMOD_DEVICE_SYMBOL_NAME);
  if (NT_SUCCESS(status))
  {
    KM_LOG_INFO("KMOD deinitialized\n");
  }
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING regPath)
{
  UNREFERENCED_PARAMETER(regPath);
  NTSTATUS status = STATUS_SUCCESS;
  driver->DriverUnload = DriverUnload;
  for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
    driver->MajorFunction[i] = OnIrpDflt;
  driver->MajorFunction[IRP_MJ_CREATE] = OnIrpCreate;
  driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OnIrpCtrl;
  driver->MajorFunction[IRP_MJ_CLOSE] = OnIrpClose;
  status = CreateDevice(driver, Device, KMOD_DEVICE_NAME, KMOD_DEVICE_SYMBOL_NAME);
  if (NT_SUCCESS(status))
  {
    KM_LOG_INFO("KMOD initialized\n");
  }
  return status;
}
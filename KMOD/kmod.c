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
#include "scanner.h"
#include "debugger.h"

/*
* Hints:
*  - https://github.com/reactos/reactos/blob/master/drivers/base/kdgdb/gdb_input.c
*  - https://github.com/ReClassNET/ReClass.NET/blob/master/NativeCore/Windows/Debugger.cpp
*  - https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-debug_event
*  - https://docs.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-waitfordebugevent
*  - https://cpp.hotexamples.com/de/examples/-/-/GetThreadContext/cpp-getthreadcontext-function-examples.html
*  - https://cpp.hotexamples.com/examples/-/ThreadContext/-/cpp-threadcontext-class-examples.html
*  - https://github.com/cheat-engine/cheat-engine/blob/master/DBKKernel/debugger.c
*  - https://github.com/cheat-engine/cheat-engine/blob/master/DBKKernel/interruptHook.c
*/

/*
* Functions:
*  - KeQueryRuntimeThread
*  - PsGetCurrentThreadStackBase
*/

/*
* Global tracing state.
*/

ULONG TraceId = 0;
TRACE_CONTEXT TraceContexts[64];

/*
* Write request/response handlers.
*/

NTSTATUS
KmHandleWriteMemoryProcess(
  PWRITE_MEMORY_PROCESS request)
{
  NTSTATUS status = STATUS_SUCCESS;
  PVOID base = NULL;
  status = KmGetProcessImageBase(request->Pid, request->ImageName, &base);
  if (NT_SUCCESS(status))
  {
    status = KmWriteMemoryProcess(request->Pid, (PVOID)((PBYTE)base + request->Offset), request->Size, request->Bytes);
    if (NT_SUCCESS(status))
    {
      KM_LOG_INFO("Write successfull\n");
    }
  }
  return status;
}

NTSTATUS
KmHandleWriteMemoryKernel(
  PWRITE_MEMORY_KERNEL request)
{
  NTSTATUS status = STATUS_SUCCESS;
  PVOID base = NULL;
  status = KmGetKernelImageBase(request->ImageName, &base);
  if (NT_SUCCESS(status))
  {
    status = KmWriteMemoryKernel((PVOID)((PBYTE)base + request->Offset), request->Size, request->Bytes);
    if (NT_SUCCESS(status))
    {
      KM_LOG_INFO("Write successfull\n");
    }
  }
  return status;
}

/*
* Read request/response handlers.
*/

NTSTATUS
KmHandleReadMemoryProcess(
  PREAD_MEMORY_PROCESS request,
  PVOID response)
{
  NTSTATUS status = STATUS_SUCCESS;
  PVOID base = NULL;
  status = KmGetProcessImageBase(request->Pid, request->ImageName, &base);
  if (NT_SUCCESS(status))
  {
    status = KmReadMemoryProcess(request->Pid, (PVOID)((PBYTE)base + request->Offset), request->Size, response);
    if (NT_SUCCESS(status))
    {
      KM_LOG_INFO("Read successfull\n");
    }
  }
  return status;
}

NTSTATUS
KmHandleReadMemoryKernel(
  PREAD_MEMORY_KERNEL request,
  PVOID response)
{
  NTSTATUS status = STATUS_SUCCESS;
  PVOID base = NULL;
  status = KmGetKernelImageBase(request->ImageName, &base);
  if (NT_SUCCESS(status))
  {
    status = KmReadMemoryKernel((PVOID)((PBYTE)base + request->Offset), request->Size, response);
    if (NT_SUCCESS(status))
    {
      KM_LOG_INFO("Read successfull\n");
    }
  }
  return status;
}

NTSTATUS
KmHandleReadModulesProcess(
  PREAD_MODULES_PROCESS request,
  PVOID response)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  PEPROCESS process = NULL;
  KAPC_STATE apc;
  status = PsLookupProcessByProcessId((HANDLE)request->Pid, &process);
  if (NT_SUCCESS(status))
  {
    status = STATUS_UNSUCCESSFUL;
    PKM_MODULE_PROCESS asyncBuffer = (PKM_MODULE_PROCESS)KmAllocateMemory(TRUE, sizeof(KM_MODULE_PROCESS) * request->Size);
    if (asyncBuffer)
    {
      KeStackAttachProcess(process, &apc);
      __try
      {
        PPEB64 peb = (PPEB64)PsGetProcessPeb(process);
        if (peb)
        {
          PVOID imageBase = peb->ImageBaseAddress;
          PLDR_DATA_TABLE_ENTRY modules = CONTAINING_RECORD(peb->Ldr->InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
          PLDR_DATA_TABLE_ENTRY module = NULL;
          PLIST_ENTRY moduleHead = modules->InMemoryOrderLinks.Flink;
          PLIST_ENTRY moduleEntry = moduleHead->Flink;
          ULONG count = 0;
          while (moduleEntry != moduleHead)
          {
            module = CONTAINING_RECORD(moduleEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            if (module && module->DllBase)
            {
              KmInterlockedMemcpy(asyncBuffer[count].Name, module->BaseDllName.Buffer, module->BaseDllName.Length, KernelMode);
              KmInterlockedMemcpy(&asyncBuffer[count].Base, &module->DllBase, sizeof(ULONG64), KernelMode);
              KmInterlockedMemcpy(&asyncBuffer[count].Size, &module->SizeOfImage, sizeof(ULONG), KernelMode);
              count++;
              if (count >= request->Size)
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
      memcpy(response, asyncBuffer, sizeof(KM_MODULE_PROCESS) * request->Size);
      KmFreeMemory(asyncBuffer);
      ObDereferenceObject(process);
    }
  }
  return status;
}

NTSTATUS
KmHandleReadModulesKernel(
  PREAD_MODULES_KERNEL request,
  PVOID response)
{
  NTSTATUS status = STATUS_SUCCESS;
  PRTL_PROCESS_MODULES buffer = (PRTL_PROCESS_MODULES)KmAllocateMemory(TRUE, sizeof(RTL_PROCESS_MODULES) * 1024 * 1024);
  if (buffer)
  {
    status = ZwQuerySystemInformation(SystemModuleInformation, buffer, sizeof(RTL_PROCESS_MODULES) * 1024 * 1024, NULL);
    if (NT_SUCCESS(status))
    {
      for (ULONG i = 0; i < min(buffer[0].NumberOfModules, request->Size); ++i)
      {
        KmInterlockedMemcpy(((PKM_MODULE_KERNEL)response)[i].Name, buffer[0].Modules[i].FullPathName + buffer[0].Modules[i].OffsetToFileName, strlen((PCHAR)(buffer[0].Modules[i].FullPathName + buffer[0].Modules[i].OffsetToFileName)), KernelMode);
        KmInterlockedMemcpy(&((PKM_MODULE_KERNEL)response)[i].Base, &buffer[0].Modules[i].ImageBase, sizeof(ULONG64), KernelMode);
        KmInterlockedMemcpy(&((PKM_MODULE_KERNEL)response)[i].Size, &buffer[0].Modules[i].ImageSize, sizeof(ULONG), KernelMode);
      }
    }
    KmFreeMemory(buffer);
  }
  return status;
}

NTSTATUS
KmHandleReadThreadsProcess(
  PREAD_THREADS_PROCESS request,
  PVOID response)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  ULONG threadCount = 0;
  KM_THREAD_PROCESS threads[1024];
  status = KmGetProcessThreads(request->Pid, &threadCount, threads);
  if (NT_SUCCESS(status))
  {
    memcpy(response, threads, sizeof(KM_THREAD_PROCESS) * request->Size);
    KM_LOG_INFO("Fetched %u threads for process %u\n", threadCount, request->Pid);
  }
  return status;
}

NTSTATUS
KmHandleReadScanResults(
  PREAD_SCAN_RESULTS request,
  PVOID response)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  return status;
}

/*
* Trace request/response handlers.
*/

NTSTATUS
KmHandleTraceContextStart(
  PTRACE_CONTEXT_START request,
  PVOID response)
{
  NTSTATUS status = STATUS_SUCCESS;
  memset(&TraceContexts[TraceId], 0, sizeof(TraceContexts[TraceId]));
  status = KmGetProcessThreads(request->Pid, &TraceContexts[TraceId].ThreadCount, TraceContexts[TraceId].Threads);
  if (NT_SUCCESS(status))
  {
    TraceContexts[TraceId].Running = TRUE;
    TraceContexts[TraceId].Id = TraceId;
    TraceContexts[TraceId].Pid = request->Pid;
    TraceContexts[TraceId].Address = request->Address;
    status = PsCreateSystemThread(&TraceContexts[TraceId].Thread, STANDARD_RIGHTS_ALL, NULL, NULL, NULL, KmTraceThread, &TraceContexts[TraceId]);
    if (NT_SUCCESS(status))
    {
      KeInitializeEvent(&TraceContexts[TraceId].Event, SynchronizationEvent, FALSE);
      KM_LOG_INFO("Trace thread started\n");
      *(PULONG)response = TraceId++;
    }
  }
  return status;
}

NTSTATUS
KmHandleTraceContextStop(
  PTRACE_CONTEXT_STOP request,
  PVOID response)
{
  NTSTATUS status = STATUS_SUCCESS;
  TraceContexts[request->Id].Running = FALSE;
  status = KeWaitForSingleObject(&TraceContexts[request->Id].Event, Executive, KernelMode, FALSE, NULL);
  if (NT_SUCCESS(status))
  {
    status = ZwClose(TraceContexts[request->Id].Thread);
    if (NT_SUCCESS(status))
    {
      memcpy(response, TraceContexts[request->Id].OpCodes, sizeof(TraceContexts[request->Id].OpCodes));
      KM_LOG_INFO("Trace thread stopped\n");
    }
  }
  return status;
}

/*
* Debug request/response handlers.
*/

NTSTATUS
KmHandleDebugBreakpointSet(
  PDEBUG_BREAKPOINT_SET request,
  PVOID response)
{
  NTSTATUS status = STATUS_SUCCESS;
  return status;
}

NTSTATUS
KmHandleDebugBreakpointRem(
  PDEBUG_BREAKPOINT_REM request,
  PVOID response)
{
  NTSTATUS status = STATUS_SUCCESS;
  return status;
}

/*
* Scan request/response handlers.
*/

NTSTATUS
KmHandleScanNew(
  PSCAN_NEW request,
  PVOID response)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  return status;
}

NTSTATUS
KmHandleScanUndo(
  PSCAN_UNDO request,
  PVOID response)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  return status;
}

NTSTATUS
KmHandleScanInt(
  PSCAN_INT request,
  PVOID response)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  PVOID base = NULL;
  SIZE_T size = 0;
  switch (request->Signedness)
  {
    case Signed:
    {
      switch (request->Width)
      {
        case x8: status = KmScanIntSigned8(base, size, request->Value.V8); break;
        case x16: status = KmScanIntSigned16(base, size, request->Value.V16); break;
        case x32: status = KmScanIntSigned32(base, size, request->Value.V32); break;
      }
      break;
    }
    case Unsigned:
    {
      switch (request->Width)
      {
        case x8: status = KmScanIntUnsigned8(base, size, request->Value.V8); break;
        case x16: status = KmScanIntUnsigned16(base, size, request->Value.V16); break;
        case x32: status = KmScanIntUnsigned32(base, size, request->Value.V32); break;
      }
      break;
    }
  }
  return status;
}

NTSTATUS
KmHandleScanReal(
  PSCAN_REAL request,
  PVOID response)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  PVOID base = NULL;
  SIZE_T size = 0;
  switch (request->Width)
  {
    case x32: status = KmScanReal32(base, size, request->Value.V32); break;
    case x64: status = KmScanReal64(base, size, request->Value.V64); break;
  }
  return status;
}

NTSTATUS
KmHandleScanBytes(
  PSCAN_BYTES request,
  PVOID response)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  PVOID base = NULL;
  SIZE_T size = 0;
  status = KmScanBytes(base, size, request->Bytes, request->Size);
  return status;
}

NTSTATUS
KmHandleScanFilterChanged(
  PSCAN_FILTER_CHANGED request,
  PVOID response)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  return status;
}

NTSTATUS
KmHandleScanFilterUnchanged(
  PSCAN_FILTER_UNCHANGED request,
  PVOID response)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  return status;
}

NTSTATUS
KmHandleScanFilterIncreased(
  PSCAN_FILTER_INCREASED request,
  PVOID response)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  return status;
}

NTSTATUS
KmHandleScanFilterDecreased(
  PSCAN_FILTER_DECREASED request,
  PVOID response)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  return status;
}

/*
* I/O callbacks.
*/

NTSTATUS
OnIrpDflt(
  PDEVICE_OBJECT device,
  PIRP irp)
{
  UNREFERENCED_PARAMETER(device);
  irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
  irp->IoStatus.Information = 0;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return irp->IoStatus.Status;
}

NTSTATUS
OnIrpCreate(
  PDEVICE_OBJECT device,
  PIRP irp)
{
  UNREFERENCED_PARAMETER(device);
  irp->IoStatus.Status = STATUS_SUCCESS;
  irp->IoStatus.Information = 0;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return irp->IoStatus.Status;
}

NTSTATUS
OnIrpCtrl(
  PDEVICE_OBJECT device,
  PIRP irp)
{
  UNREFERENCED_PARAMETER(device);
  KM_LOG_ENTER_FUNCTION(, OnIrpCtrl);
  PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
  __try
  {
    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
      case KM_WRITE_MEMORY_PROCESS:
      {
        KM_LOG_INFO("Begin write memory process\n");
        WRITE_MEMORY_PROCESS request = *(PWRITE_MEMORY_PROCESS)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = KmHandleWriteMemoryProcess(&request);
        irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? 0 : 0;
        KM_LOG_INFO("End write memory process\n");
        break;
      }
      case KM_WRITE_MEMORY_KERNEL:
      {
        KM_LOG_INFO("Begin write memory kernel\n");
        WRITE_MEMORY_KERNEL request = *(PWRITE_MEMORY_KERNEL)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = KmHandleWriteMemoryKernel(&request);
        irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? 0 : 0;
        KM_LOG_INFO("End write memory kernel\n");
        break;
      }
      case KM_READ_MEMORY_PROCESS:
      {
        KM_LOG_INFO("Begin read memory process\n");
        READ_MEMORY_PROCESS request = *(PREAD_MEMORY_PROCESS)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = KmHandleReadMemoryProcess(&request, irp->AssociatedIrp.SystemBuffer);
        irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? sizeof(BYTE) * request.Size : 0;
        KM_LOG_INFO("End read memory process\n");
        break;
      }
      case KM_READ_MEMORY_KERNEL:
      {
        KM_LOG_INFO("Begin read memory kernel\n");
        READ_MEMORY_KERNEL request = *(PREAD_MEMORY_KERNEL)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = KmHandleReadMemoryKernel(&request, irp->AssociatedIrp.SystemBuffer);
        irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? sizeof(BYTE) * request.Size : 0;
        KM_LOG_INFO("End read memory kernel\n");
        break;
      }
      case KM_READ_MODULES_PROCESS:
      {
        KM_LOG_INFO("Begin read modules process\n");
        READ_MODULES_PROCESS request = *(PREAD_MODULES_PROCESS)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = KmHandleReadModulesProcess(&request, irp->AssociatedIrp.SystemBuffer);
        irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? sizeof(KM_MODULE_PROCESS) * request.Size : 0;
        KM_LOG_INFO("End read modules process\n");
        break;
      }
      case KM_READ_MODULES_KERNEL:
      {
        KM_LOG_INFO("Begin read modules kernel\n");
        READ_MODULES_KERNEL request = *(PREAD_MODULES_KERNEL)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = KmHandleReadModulesKernel(&request, irp->AssociatedIrp.SystemBuffer);
        irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? sizeof(KM_MODULE_KERNEL) * request.Size : 0;
        KM_LOG_INFO("End read modules kernel\n");
        break;
      }
      case KM_READ_THREADS_PROCESS:
      {
        KM_LOG_INFO("Begin read thread process\n");
        READ_THREADS_PROCESS request = *(PREAD_THREADS_PROCESS)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = KmHandleReadThreadsProcess(&request, irp->AssociatedIrp.SystemBuffer);
        irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? sizeof(KM_THREAD_PROCESS) * request.Size : 0;
        KM_LOG_INFO("End read thread process\n");
        break;
      }
      case KM_READ_SCAN_RESULTS:
      {
        KM_LOG_INFO("Begin read scan results\n");
        READ_SCAN_RESULTS request = *(PREAD_SCAN_RESULTS)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = KmHandleReadScanResults(&request, irp->AssociatedIrp.SystemBuffer);
        irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? 0 : 0;
        KM_LOG_INFO("End read scan results\n");
        break;
      }
      case KM_TRACE_CONTEXT_START:
      {
        KM_LOG_INFO("Begin trace context start\n");
        TRACE_CONTEXT_START request = *(PTRACE_CONTEXT_START)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = KmHandleTraceContextStart(&request, irp->AssociatedIrp.SystemBuffer);
        irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? sizeof(ULONG) : 0;
        KM_LOG_INFO("End trace context start\n");
        break;
      }
      case KM_TRACE_CONTEXT_STOP:
      {
        KM_LOG_INFO("Begin trace context stop\n");
        TRACE_CONTEXT_STOP request = *(PTRACE_CONTEXT_STOP)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = KmHandleTraceContextStop(&request, irp->AssociatedIrp.SystemBuffer);
        irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? sizeof(ULONG64) * 64 : 0;
        KM_LOG_INFO("End trace context stop\n");
        break;
      }
      case KM_DEBUG_BREAKPOINT_SET:
      {
        KM_LOG_INFO("Begin debug breakpoint set\n");
        DEBUG_BREAKPOINT_SET request = *(PDEBUG_BREAKPOINT_SET)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = KmHandleDebugBreakpointSet(&request, irp->AssociatedIrp.SystemBuffer);
        irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? 0 : 0;
        KM_LOG_INFO("End debug breakpoint set\n");
        break;
      }
      case KM_DEBUG_BREAKPOINT_REM:
      {
        KM_LOG_INFO("Begin debug breakpoint rem\n");
        DEBUG_BREAKPOINT_REM request = *(PDEBUG_BREAKPOINT_REM)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = KmHandleDebugBreakpointRem(&request, irp->AssociatedIrp.SystemBuffer);
        irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? 0 : 0;
        KM_LOG_INFO("End debug breakpoint rem\n");
        break;
      }
      case KM_SCAN_NEW:
      {
        KM_LOG_INFO("Begin scan new\n");
        SCAN_NEW request = *(PSCAN_NEW)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = KmHandleScanNew(&request, irp->AssociatedIrp.SystemBuffer);
        irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? 0 : 0;
        KM_LOG_INFO("End scan new\n");
        break;
      }
      case KM_SCAN_UNDO:
      {
        KM_LOG_INFO("Begin scan undo\n");
        SCAN_UNDO request = *(PSCAN_UNDO)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = KmHandleScanUndo(&request, irp->AssociatedIrp.SystemBuffer);
        irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? 0 : 0;
        KM_LOG_INFO("End scan undo\n");
        break;
      }
      case KM_SCAN_INT:
      {
        KM_LOG_INFO("Begin scan int\n");
        SCAN_INT request = *(PSCAN_INT)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = KmHandleScanInt(&request, irp->AssociatedIrp.SystemBuffer);
        irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? 0 : 0;
        KM_LOG_INFO("End scan int\n");
        break;
      }
      case KM_SCAN_REAL:
      {
        KM_LOG_INFO("Begin scan real\n");
        SCAN_REAL request = *(PSCAN_REAL)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = KmHandleScanReal(&request, irp->AssociatedIrp.SystemBuffer);
        irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? 0 : 0;
        KM_LOG_INFO("End scan real\n");
        break;
      }
      case KM_SCAN_BYTES:
      {
        KM_LOG_INFO("Begin scan bytes\n");
        SCAN_BYTES request = *(PSCAN_BYTES)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = KmHandleScanBytes(&request, irp->AssociatedIrp.SystemBuffer);
        irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? 0 : 0;
        KM_LOG_INFO("End scan bytes\n");
        break;
      }
      case KM_SCAN_FILTER_CHANGED:
      {
        KM_LOG_INFO("Begin scan filter changed\n");
        SCAN_FILTER_CHANGED request = *(PSCAN_FILTER_CHANGED)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = KmHandleScanFilterChanged(&request, irp->AssociatedIrp.SystemBuffer);
        irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? 0 : 0;
        KM_LOG_INFO("End scan filter changed\n");
        break;
      }
      case KM_SCAN_FILTER_UNCHANGED:
      {
        KM_LOG_INFO("Begin scan filter unchanged\n");
        SCAN_FILTER_UNCHANGED request = *(PSCAN_FILTER_UNCHANGED)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = KmHandleScanFilterUnchanged(&request, irp->AssociatedIrp.SystemBuffer);
        irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? 0 : 0;
        KM_LOG_INFO("End scan filter unchanged\n");
        break;
      }
      case KM_SCAN_FILTER_INCREASED:
      {
        KM_LOG_INFO("Begin scan filter increased\n");
        SCAN_FILTER_INCREASED request = *(PSCAN_FILTER_INCREASED)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = KmHandleScanFilterIncreased(&request, irp->AssociatedIrp.SystemBuffer);
        irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? 0 : 0;
        KM_LOG_INFO("End scan filter increased\n");
        break;
      }
      case KM_SCAN_FILTER_DECREASED:
      {
        KM_LOG_INFO("Begin scan filter decreased\n");
        SCAN_FILTER_DECREASED request = *(PSCAN_FILTER_DECREASED)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = KmHandleScanFilterDecreased(&request, irp->AssociatedIrp.SystemBuffer);
        irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? 0 : 0;
        KM_LOG_INFO("End scan filter decreased\n");
        break;
      }
    }
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    KM_LOG_ERROR("Something went wrong\n");
    irp->IoStatus.Status = STATUS_UNHANDLED_EXCEPTION;
    irp->IoStatus.Information = 0;
  }
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  KM_LOG_EXIT_FUNCTION(, OnIrpCtrl);
  return irp->IoStatus.Status;
}

NTSTATUS
OnIrpClose(
  PDEVICE_OBJECT device,
  PIRP irp)
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

#define KM_DEVICE_NAME L"\\Device\\KMOD"
#define KM_DEVICE_SYMBOL_NAME L"\\DosDevices\\KMOD"

/*
* Entry point.
*/

VOID
DriverUnload(
  PDRIVER_OBJECT driver)
{
  UNREFERENCED_PARAMETER(driver);
  NTSTATUS status = STATUS_SUCCESS;
  status = DeleteDevice(Device, KM_DEVICE_SYMBOL_NAME);
  if (NT_SUCCESS(status))
  {
    KM_LOG_INFO("KMOD deinitialized\n");
  }
}

NTSTATUS
DriverEntry(
  PDRIVER_OBJECT driver,
  PUNICODE_STRING regPath)
{
  UNREFERENCED_PARAMETER(regPath);
  NTSTATUS status = STATUS_SUCCESS;
  driver->DriverUnload = DriverUnload;
  for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
    driver->MajorFunction[i] = OnIrpDflt;
  driver->MajorFunction[IRP_MJ_CREATE] = OnIrpCreate;
  driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OnIrpCtrl;
  driver->MajorFunction[IRP_MJ_CLOSE] = OnIrpClose;
  status = CreateDevice(driver, &Device, KM_DEVICE_NAME, KM_DEVICE_SYMBOL_NAME);
  if (NT_SUCCESS(status))
  {
    __try
    {
      KmInitializeDebugger();
      KM_LOG_INFO("KMOD initialized\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
      KM_LOG_ERROR("Something went wrong\n");
      status = STATUS_UNHANDLED_EXCEPTION;
    }
  }
  return status;
}
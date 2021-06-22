#include "kdrv.h"
#include "mem.h"
#include "pe.h"
#include "undoc.h"
#include "device.h"
#include "proc.h"
#include "util.h"

// Global device/symbol names
#define KDRV_DEVICE_NAME L"\\Device\\KDRV"
#define KDRV_DEVICE_SYMBOL_NAME L"\\DosDevices\\KDRV"

// Global cmd device
PDEVICE_OBJECT Device = NULL;

NTSTATUS Initialize(PDRIVER_OBJECT driver)
{
  NTSTATUS status = STATUS_SUCCESS;
  // Create cmd device
  UNICODE_STRING deviceName;
  UNICODE_STRING symbolicName;
  RtlInitUnicodeString(&deviceName, KDRV_DEVICE_NAME);
  RtlInitUnicodeString(&symbolicName, KDRV_DEVICE_SYMBOL_NAME);
  status = CreateDevice(driver, Device, &deviceName, &symbolicName);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("CreateDevice\n");
    return status;
  }
  return status;
}
NTSTATUS DeInitialize(PDRIVER_OBJECT driver)
{
  UNREFERENCED_PARAMETER(driver);
  NTSTATUS status = STATUS_SUCCESS;
  // Delete cmd device
  UNICODE_STRING symbolicName;
  RtlInitUnicodeString(&symbolicName, KDRV_DEVICE_SYMBOL_NAME);
  status = DeleteDevice(Device, &symbolicName);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("DeleteDevice\n");
    return status;
  }
  return status;
}

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
  LOG_INFO("Received create request\n");
  irp->IoStatus.Status = STATUS_SUCCESS;
  irp->IoStatus.Information = 0;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return irp->IoStatus.Status;
}
NTSTATUS OnIrpIoCtrl(PDEVICE_OBJECT device, PIRP irp)
{
  UNREFERENCED_PARAMETER(device);
  LOG_INFO("Received ioctrl request\n");
  irp->IoStatus.Status = STATUS_SUCCESS;
  irp->IoStatus.Information = 0;
  PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
  PEPROCESS process = NULL;
  PETHREAD thread = NULL;
  __try
  {
    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
      case KDRV_CTRL_DUMP_MODULES:
      {
        PKDRV_REQ_DUMP_MODULES request = (PKDRV_REQ_DUMP_MODULES)MmGetSystemAddressForMdl(irp->MdlAddress);
        switch (request->Mode)
        {
          case KDRV_REQ_DUMP_MODULES::Kernel:
          {
            GetKernelModules(request, TRUE);
            break;
          }
          case KDRV_REQ_DUMP_MODULES::User:
          {
            irp->IoStatus.Status = PsLookupProcessByProcessId((HANDLE)request->Pid, &process);
            LOG_ERROR_IF_NOT_SUCCESS(irp->IoStatus.Status, "PsLookupProcessByProcessId %X\n", irp->IoStatus.Status);
            GetUserModules(process, request, TRUE);
            break;
          }
        }
        irp->IoStatus.Information = sizeof(KDRV_REQ_DUMP_MODULES);
        break;
      }
      case KDRV_CTRL_DUMP_THREADS:
      {
        PKDRV_REQ_DUMP_THREADS request = (PKDRV_REQ_DUMP_THREADS)MmGetSystemAddressForMdl(irp->MdlAddress);
        irp->IoStatus.Status = PsLookupProcessByProcessId((HANDLE)request->Pid, &process);
        LOG_ERROR_IF_NOT_SUCCESS(irp->IoStatus.Status, "PsLookupProcessByProcessId %X\n", irp->IoStatus.Status);
        irp->IoStatus.Status = PsLookupThreadByThreadId((HANDLE)request->Tid, &thread);
        LOG_ERROR_IF_NOT_SUCCESS(irp->IoStatus.Status, "PsLookupThreadByThreadId %X\n", irp->IoStatus.Status);
        DumpToFile(L"\\??\\C:\\Users\\Test\\Desktop\\krnl_thread_dump.txt", thread, sizeof(ETHREAD));
        if (thread)
        {
          //LOG_INFO("Pid: %u\n", *(PULONG)((ETHREAD*)thread)->Cid.UniqueProcess);
          //LOG_INFO("Tid: %u\n", *(PULONG)((ETHREAD*)thread)->Cid.UniqueThread);
          //LOG_INFO("Cid: %u\n", *(PULONG)((ETHREAD*)thread)->Cid.UniqueProcess);
          //LOG_INFO("Base: %p\n", ((ETHREAD*)thread)->Shadow.StartAddress);
        }
        ObDereferenceObject(thread);
        break;
      }
      case KDRV_CTRL_DUMP_REGISTERS:
      {
        PKDRV_REQ_DUMP_REGISTERS request = (PKDRV_REQ_DUMP_REGISTERS)MmGetSystemAddressForMdl(irp->MdlAddress);
        irp->IoStatus.Status = PsLookupProcessByProcessId((HANDLE)request->Pid, &process);
        LOG_ERROR_IF_NOT_SUCCESS(irp->IoStatus.Status, "PsLookupProcessByProcessId %X\n", irp->IoStatus.Status);
        irp->IoStatus.Status = PsLookupThreadByThreadId((HANDLE)request->Tid, &thread);
        LOG_ERROR_IF_NOT_SUCCESS(irp->IoStatus.Status, "PsLookupThreadByThreadId %X\n", irp->IoStatus.Status);
        PCONTEXT context = NULL;
        SIZE_T contextSize = sizeof(CONTEXT);
        irp->IoStatus.Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID*)&context, 0, &contextSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        LOG_ERROR_IF_NOT_SUCCESS(irp->IoStatus.Status, "ZwAllocateVirtualMemory %X\n", irp->IoStatus.Status);
        RtlZeroMemory(context, sizeof(CONTEXT));
        context->ContextFlags = CONTEXT_ALL;
        irp->IoStatus.Status = PsGetContextThread(thread, context, UserMode);
        LOG_ERROR_IF_NOT_SUCCESS(irp->IoStatus.Status, "PsGetContextThread %X\n", irp->IoStatus.Status);
        DumpToFile(L"\\??\\C:\\Users\\Test\\Desktop\\krnl_register_dump.txt", context, sizeof(CONTEXT));
        LOG_INFO("Control flags\n");
        LOG_INFO("ContextFlags: %u\n", context->ContextFlags);
        LOG_INFO("MxCsr: %u\n", context->MxCsr);
        LOG_INFO("\n");
        LOG_INFO("Segment registers and processor flags\n");
        LOG_INFO("SegCs: %u\n", context->SegCs);
        LOG_INFO("SegDs: %u\n", context->SegDs);
        LOG_INFO("SegEs: %u\n", context->SegEs);
        LOG_INFO("SegFs: %u\n", context->SegFs);
        LOG_INFO("SegGs: %u\n", context->SegGs);
        LOG_INFO("SegSs: %u\n", context->SegSs);
        LOG_INFO("EFlags: %u\n", context->EFlags);
        LOG_INFO("\n");
        LOG_INFO("Debug registers\n");
        LOG_INFO("Dr0: %llu\n", context->Dr0);
        LOG_INFO("Dr1: %llu\n", context->Dr1);
        LOG_INFO("Dr2: %llu\n", context->Dr2);
        LOG_INFO("Dr3: %llu\n", context->Dr3);
        LOG_INFO("Dr6: %llu\n", context->Dr6);
        LOG_INFO("Dr7: %llu\n", context->Dr7);
        LOG_INFO("\n");
        LOG_INFO("Integer registers\n");
        LOG_INFO("Rax: %llu\n", context->Rax);
        LOG_INFO("Rcx: %llu\n", context->Rcx);
        LOG_INFO("Rdx: %llu\n", context->Rdx);
        LOG_INFO("Rbx: %llu\n", context->Rbx);
        LOG_INFO("Rsp: %llu\n", context->Rsp);
        LOG_INFO("Rbp: %llu\n", context->Rbp);
        LOG_INFO("Rsi: %llu\n", context->Rsi);
        LOG_INFO("Rdi: %llu\n", context->Rdi);
        LOG_INFO("R8: %llu\n", context->R8);
        LOG_INFO("R9: %llu\n", context->R9);
        LOG_INFO("R10: %llu\n", context->R10);
        LOG_INFO("R11: %llu\n", context->R11);
        LOG_INFO("R12: %llu\n", context->R12);
        LOG_INFO("R13: %llu\n", context->R13);
        LOG_INFO("R14: %llu\n", context->R14);
        LOG_INFO("R15: %llu\n", context->R15);
        LOG_INFO("\n");
        LOG_INFO("Program counter\n");
        LOG_INFO("Rip: %llu\n", context->Rip);
        LOG_INFO("\n");
        LOG_INFO("Special debug control registers\n");
        LOG_INFO("DebugControl: %llu\n", context->DebugControl);
        LOG_INFO("LastBranchToRip: %llu\n", context->LastBranchToRip);
        LOG_INFO("LastBranchFromRip: %llu\n", context->LastBranchFromRip);
        LOG_INFO("LastExceptionToRip: %llu\n", context->LastExceptionToRip);
        LOG_INFO("LastExceptionFromRip: %llu\n", context->LastExceptionFromRip);
        SIZE_T regionSize = 0;
        irp->IoStatus.Status = ZwFreeVirtualMemory(ZwCurrentProcess(), (PVOID*)&context, &regionSize, MEM_RELEASE);
        LOG_ERROR_IF_NOT_SUCCESS(irp->IoStatus.Status, "ZwFreeVirtualMemory %X\n", irp->IoStatus.Status);
        break;
      }
      case KDRV_CTRL_THREAD_SUSPEND:
      {
        PKDRV_REQ_THREAD_SUSPEND request = (PKDRV_REQ_THREAD_SUSPEND)MmGetSystemAddressForMdl(irp->MdlAddress);
        irp->IoStatus.Status = PsLookupProcessByProcessId((HANDLE)request->Pid, &process);
        LOG_ERROR_IF_NOT_SUCCESS(irp->IoStatus.Status, "Failed finding process\n");
        irp->IoStatus.Status = PsSuspendProcess(process);
        LOG_ERROR_IF_NOT_SUCCESS(irp->IoStatus.Status, "PsSuspendProcess %X\n", irp->IoStatus.Status);
        // TODO: impl for KeSuspendThread ...
        break;
      }
      case KDRV_CTRL_THREAD_RESUME:
      {
        PKDRV_REQ_THREAD_RESUME request = (PKDRV_REQ_THREAD_RESUME)MmGetSystemAddressForMdl(irp->MdlAddress);
        irp->IoStatus.Status = PsLookupProcessByProcessId((HANDLE)request->Pid, &process);
        LOG_ERROR_IF_NOT_SUCCESS(irp->IoStatus.Status, "Failed finding process\n");
        irp->IoStatus.Status = PsResumeProcess(process);
        LOG_ERROR_IF_NOT_SUCCESS(irp->IoStatus.Status, "PsResumeProcess %X\n", irp->IoStatus.Status);
        // TODO: impl for KeResumeThread ...
        break;
      }
    }
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    if (process != NULL)
    {
      LOG_INFO("Exception cleanup handler executed\n");
      ObDereferenceObject(process);
      process = NULL;
    }
    if (thread != NULL)
    {
      LOG_INFO("Exception cleanup handler executed\n");
      ObDereferenceObject(thread);
      thread = NULL;
    }
    LOG_ERROR("Something went wrong\n");
  }
  if (process != NULL)
  {
    LOG_INFO("Default cleanup handler executed\n");
    ObDereferenceObject(process);
    process = NULL;
  }
  if (thread != NULL)
  {
    LOG_INFO("Default cleanup handler executed\n");
    ObDereferenceObject(thread);
    thread = NULL;
  }
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return irp->IoStatus.Status;
}
NTSTATUS OnIrpClose(PDEVICE_OBJECT device, PIRP irp)
{
  UNREFERENCED_PARAMETER(device);
  LOG_INFO("Received close request\n");
  irp->IoStatus.Status = STATUS_SUCCESS;
  irp->IoStatus.Information = 0;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return irp->IoStatus.Status;
}

VOID DriverUnload(PDRIVER_OBJECT driver)
{
  NTSTATUS status = DeInitialize(driver);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("KDRV failed while deinitializing\n");
    return;
  }
  LOG_INFO("KDRV deinitialized\n");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING regPath)
{
  UNREFERENCED_PARAMETER(regPath);
  NTSTATUS status = STATUS_SUCCESS;
  // Initialize kernel driver
  status = Initialize(driver);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("KDRV failed while initializing\n");
    return status;
  }
  LOG_INFO("KDRV initialized\n");
  // Register driver callbacks
  driver->DriverUnload = DriverUnload;
  // Register default interrupt callbacks
  for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
    driver->MajorFunction[i] = OnIrpDflt;
  // Register interrupt callbacks
  driver->MajorFunction[IRP_MJ_CREATE] = OnIrpCreate;
  driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OnIrpIoCtrl;
  driver->MajorFunction[IRP_MJ_CLOSE] = OnIrpClose;
  return status;
}
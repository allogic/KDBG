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
            LOG_ERROR_IF_NOT_SUCCESS(irp->IoStatus.Status, "Failed finding process\n");
            GetUserModules(process, request, TRUE);
            break;
          }
        }
        irp->IoStatus.Information = sizeof(KDRV_REQ_DUMP_MODULES);
        break;
      }
      case KDRV_CTRL_DUMP_THREADS:
      {
        PKDRV_REQ_DUMP_THREADS request = (PKDRV_REQ_DUMP_THREADS)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = PsLookupProcessByProcessId((HANDLE)request->Pid, &process);
        LOG_ERROR_IF_NOT_SUCCESS(irp->IoStatus.Status, "Failed finding process\n");
        PETHREAD thread = NULL;
        irp->IoStatus.Status = PsLookupThreadByThreadId((HANDLE)request->Tid, &thread);
        LOG_ERROR_IF_NOT_SUCCESS(irp->IoStatus.Status, "Failed finding thread %X\n", irp->IoStatus.Status);
        LOG_INFO("Found thread at %p\n", thread);
        UNICODE_STRING filePath;
        RtlInitUnicodeString(&filePath, L"\\??\\C:\\Users\\Test\\Desktop\\krnl_dump.txt");
        LOG_INFO("Dumping to file %wZ\n", filePath);
        DumpToFile(&filePath, thread, sizeof(ETHREAD));
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
        //PKDRV_REQ_DUMP_REGISTERS request = (PKDRV_REQ_DUMP_REGISTERS)irp->AssociatedIrp.SystemBuffer;
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
    LOG_ERROR("Something went wrong\n");
  }
  if (process != NULL)
  {
    LOG_INFO("Default cleanup handler executed\n");
    ObDereferenceObject(process);
    process = NULL;
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
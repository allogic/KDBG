#include "kdrv.h"
#include "mem.h"
#include "pe.h"
#include "undoc.h"
#include "device.h"
#include "proc.h"

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

NTSTATUS OnIrpDflt(PDEVICE_OBJECT deviceObject, PIRP irp)
{
  UNREFERENCED_PARAMETER(deviceObject);
  irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
  irp->IoStatus.Information = 0;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return irp->IoStatus.Status;
}
NTSTATUS OnIrpCreate(PDEVICE_OBJECT deviceObject, PIRP irp)
{
  UNREFERENCED_PARAMETER(deviceObject);
  LOG_INFO("Received create request\n");
  irp->IoStatus.Status = STATUS_SUCCESS;
  irp->IoStatus.Information = 0;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return irp->IoStatus.Status;
}
NTSTATUS OnIrpIoCtrl(PDEVICE_OBJECT deviceObject, PIRP irp)
{
  UNREFERENCED_PARAMETER(deviceObject);
  LOG_INFO("Received ioctrl request\n");
  irp->IoStatus.Status = STATUS_SUCCESS;
  irp->IoStatus.Information = 0;
  PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
  __try
  {
    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
      case KDRV_CTRL_DUMP_IMAGES:
      {
        PKDRV_REQ_DUMP_IMAGES request = (PKDRV_REQ_DUMP_IMAGES)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = GetUserImages(request->Images, request->Size);
        break;
      }
      case KDRV_CTRL_DUMP_MODULES:
      {
        PKDRV_REQ_DUMP_MODULES request = (PKDRV_REQ_DUMP_MODULES)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = GetUserImageModules(request->Pid, request->Modules, request->Size);
        break;
      }
      case KDRV_CTRL_DUMP_THREADS:
      {
        PKDRV_REQ_DUMP_THREADS request = (PKDRV_REQ_DUMP_THREADS)irp->AssociatedIrp.SystemBuffer;
        irp->IoStatus.Status = GetUserImageThreads(request->Pid, request->Threads, request->Size);
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
    LOG_ERROR("Something went wrong\n");
  }
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return irp->IoStatus.Status;
}
NTSTATUS OnIrpClose(PDEVICE_OBJECT deviceObject, PIRP irp)
{
  UNREFERENCED_PARAMETER(deviceObject);
  LOG_INFO("Received close request\n");
  irp->IoStatus.Status = STATUS_SUCCESS;
  irp->IoStatus.Information = 0;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return irp->IoStatus.Status;
}

VOID DriverUnload(PDRIVER_OBJECT driverObject)
{
  NTSTATUS status = DeInitialize(driverObject);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("KDRV failed while deinitializing\n");
    return;
  }
  LOG_INFO("KDRV deinitialized\n");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING regPath)
{
  UNREFERENCED_PARAMETER(regPath);
  NTSTATUS status = STATUS_SUCCESS;
  // Initialize kernel driver
  status = Initialize(driverObject);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("KDRV failed while initializing\n");
    return status;
  }
  LOG_INFO("KDRV initialized\n");
  // Register driver callbacks
  driverObject->DriverUnload = DriverUnload;
  // Register default interrupt callbacks
  for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
    driverObject->MajorFunction[i] = OnIrpDflt;
  // Register interrupt callbacks
  driverObject->MajorFunction[IRP_MJ_CREATE] = OnIrpCreate;
  driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OnIrpIoCtrl;
  driverObject->MajorFunction[IRP_MJ_CLOSE] = OnIrpClose;
  return status;
}
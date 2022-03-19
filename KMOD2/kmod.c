#include "global.h"
#include "device.h"
#include "ioctrl.h"
#include "interrupt.h"

/*
* I/O callbacks
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
      case KM_CTRL_DEBUG:
      {
        KM_LOG_INFO("Begin debug\n");
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = 0;
        KM_LOG_INFO("End debug\n");
      }
      default:
      {
        irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
        irp->IoStatus.Information = 0;
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
* I/O communication device
*/

PDEVICE_OBJECT Device = NULL;

#define KM_DEVICE_NAME L"\\Device\\KMOD2"
#define KM_DEVICE_SYMBOL_NAME L"\\DosDevices\\KMOD2"

/*
* Entry point
*/

VOID
DriverUnload(
  PDRIVER_OBJECT driver)
{
  UNREFERENCED_PARAMETER(driver);
  NTSTATUS status = STATUS_SUCCESS;
  status = DeleteDevice(Device, KM_DEVICE_SYMBOL_NAME);
  KmRestoreInterrupts();
  if (NT_SUCCESS(status))
  {
    KM_LOG_INFO("KMOD2 deinitialized\n");
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
  {
    driver->MajorFunction[i] = OnIrpDflt;
  }
  driver->MajorFunction[IRP_MJ_CREATE] = OnIrpCreate;
  driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OnIrpCtrl;
  driver->MajorFunction[IRP_MJ_CLOSE] = OnIrpClose;
  status = CreateDevice(driver, &Device, KM_DEVICE_NAME, KM_DEVICE_SYMBOL_NAME);
  KmInitInterrupts();
  if (NT_SUCCESS(status))
  {
    KM_LOG_INFO("KMOD2 initialized\n");
  }
  return status;
}
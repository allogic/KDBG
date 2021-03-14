#include "kdrv.h"
#include "klogic.h"
#include "ulogic.h"
#include "pe.h"
#include "undoc.h"

// Global driver state
UNICODE_STRING DeviceName;
UNICODE_STRING DeviceSymName;
PDEVICE_OBJECT DeviceObject = NULL;

NTSTATUS Initialize(PDRIVER_OBJECT driverObject)
{
  NTSTATUS status = STATUS_SUCCESS;
  // Create I/O device
  RtlInitUnicodeString(&DeviceName, L"\\Device\\KDRV");
  status = IoCreateDevice(driverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, 0, &DeviceObject);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("IoCreateDevice\n");
    return status;
  }
  DeviceObject->Flags |= (DO_DIRECT_IO | DO_BUFFERED_IO);
  DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
  // Create symbolic link
  RtlInitUnicodeString(&DeviceSymName, L"\\DosDevices\\KDRV");
  status = IoCreateSymbolicLink(&DeviceSymName, &DeviceName);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("IoCreateSymbolicLink\n");
    return status;
  }
  return status;
}
NTSTATUS DeInitialize(PDRIVER_OBJECT driverObject)
{
  UNREFERENCED_PARAMETER(driverObject);
  NTSTATUS status = STATUS_SUCCESS;
  // Destroy symbolic link
  status = IoDeleteSymbolicLink(&DeviceSymName);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("IoDeleteSymbolicLink\n");
    return status;
  }
  // Destroy I/O device
  IoDeleteDevice(DeviceObject);
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
  switch (stack->Parameters.DeviceIoControl.IoControlCode)
  {
    case KDRV_CTRL_DUMP_KERNEL_IMAGE_REQUEST:
    {
      // Kernel dump images request
      PKDRV_DUMP_KERNEL_IMAGE_REQUEST request = (PKDRV_DUMP_KERNEL_IMAGE_REQUEST)irp->AssociatedIrp.SystemBuffer;
      if (request)
      {
        irp->IoStatus.Status = GetKernelImages(request->Images, request->Size);
        if (NT_SUCCESS(irp->IoStatus.Status))
          irp->IoStatus.Information = request->Size;
      }
      break;
    }
    case KDRV_CTRL_DUMP_USER_IMAGE_REQUEST:
    {
      // User dump images request
      PKDRV_DUMP_USER_IMAGE_REQUEST request = (PKDRV_DUMP_USER_IMAGE_REQUEST)irp->AssociatedIrp.SystemBuffer;
      if (request)
      {
        irp->IoStatus.Status = GetUserImages(request->Images, request->Size);
        if (NT_SUCCESS(irp->IoStatus.Status))
          irp->IoStatus.Information = request->Size;
      }
      break;
    }
    case KDRV_CTRL_READ_KERNEL_REQUEST:
    {
      // Kernel read request
      PKDRV_READ_KERNEL_REQUEST request = (PKDRV_READ_KERNEL_REQUEST)irp->AssociatedIrp.SystemBuffer;
      if (request)
      {
        // Find image base
        PVOID imageBase = NULL;
        irp->IoStatus.Status = GetKernelImageBase(request->ImageName, imageBase);
        if (NT_SUCCESS(irp->IoStatus.Status))
        {
          // Find export base
          PVOID exportBase = RtlFindExportedRoutineByName(imageBase, request->ExportName);
          if (exportBase)
          {
            // Read kernel memeory
            irp->IoStatus.Status = TryReadKernelMemory((PVOID)((ULONG_PTR)exportBase + request->Offset), request->Buffer, request->Size);
            if (NT_SUCCESS(irp->IoStatus.Status))
              irp->IoStatus.Information = request->Size;
          }
          else
          {
            irp->IoStatus.Status = STATUS_INVALID_ADDRESS;
          }
        }
      }
      break;
    }
    case KDRV_CTRL_WRITE_KERNEL_REQUEST:
    {
      // Kernel write request
      PKDRV_WRITE_KERNEL_REQUEST request = (PKDRV_WRITE_KERNEL_REQUEST)irp->AssociatedIrp.SystemBuffer;
      if (request)
      {
        // Find image base
        PVOID imageBase = NULL;
        irp->IoStatus.Status = GetKernelImageBase(request->ImageName, imageBase);
        if (NT_SUCCESS(irp->IoStatus.Status))
        {
          // Find export base
          PVOID exportBase = RtlFindExportedRoutineByName(imageBase, request->ExportName);
          if (exportBase)
          {
            // Write kernel memeory
            irp->IoStatus.Status = TryWriteKernelMemory((PVOID)((ULONG_PTR)exportBase + request->Offset), request->Buffer, request->Size);
            if (NT_SUCCESS(irp->IoStatus.Status))
              irp->IoStatus.Information = request->Size;
          }
          else
          {
            irp->IoStatus.Status = STATUS_INVALID_ADDRESS;
          }
        }
      }
      break;
    }
    case KDRV_CTRL_READ_USER_REQUEST:
    {
      // User read request
      PKDRV_READ_USER_REQUEST request = (PKDRV_READ_USER_REQUEST)irp->AssociatedIrp.SystemBuffer;
      if (request)
      {
        // Find image base
        PVOID imageBase = NULL;
        irp->IoStatus.Status = GetUserImageBase(request->Pid, request->ModuleName, imageBase);
        if (NT_SUCCESS(irp->IoStatus.Status))
        {
          // TODO implement module wcscmp for modules

          irp->IoStatus.Status = TryReadUserMemory(request->Pid, (PVOID)((ULONG_PTR)imageBase + request->Offset), request->Buffer, request->Size);
          if (NT_SUCCESS(irp->IoStatus.Status))
            irp->IoStatus.Information = request->Size;
        }
      }
      break;
    }
    case KDRV_CTRL_WRITE_USER_REQUEST:
    {
      // User write request
      PKDRV_WRITE_USER_REQUEST request = (PKDRV_WRITE_USER_REQUEST)irp->AssociatedIrp.SystemBuffer;
      if (request)
      {
        // Find image base
        PVOID imageBase = NULL;
        irp->IoStatus.Status = GetUserImageBase(request->Pid, request->ModuleName, imageBase);
        if (NT_SUCCESS(irp->IoStatus.Status))
        {
          // TODO implement module wcscmp for modules

          irp->IoStatus.Status = TryWriteUserMemory(request->Pid, (PVOID)((ULONG_PTR)imageBase + request->Offset), request->Buffer, request->Size);
          if (NT_SUCCESS(irp->IoStatus.Status))
            irp->IoStatus.Information = request->Size;
        }
      }
      break;
    }
    case KDRV_CTRL_DEBUG_REQUEST:
    {
      // Debug request
      __try
      {
        
      }
      __except (EXCEPTION_EXECUTE_HANDLER)
      {
        LOG_ERROR("Something went wrong\n");
      }
      
      break;
    }
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

  // Reg driver callbacks
  driverObject->DriverUnload = DriverUnload;

  // Reg default irp callbacks
  for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
    driverObject->MajorFunction[i] = OnIrpDflt;

  // Reg kdrv irp callbacks
  driverObject->MajorFunction[IRP_MJ_CREATE] = OnIrpCreate;
  driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OnIrpIoCtrl;
  driverObject->MajorFunction[IRP_MJ_CLOSE] = OnIrpClose;

  return status;
}
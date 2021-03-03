#include "kdrv.h"

KDRV sKdrv;

NTSTATUS KDRV::Initialize(PDRIVER_OBJECT driverObject)
{
  // Create I/O device
  RtlInitUnicodeString(&DeviceName, L"\\Device\\KDRV");
  Status = IoCreateDevice(driverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, 0, &DeviceObject);
  if (!NT_SUCCESS(Status))
  {
    LOG_ERROR("IoCreateDevice\n");
    return Status;
  }
  DeviceObject->Flags |= (DO_DIRECT_IO | DO_BUFFERED_IO);
  DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
  // Create symbolic link
  RtlInitUnicodeString(&DeviceSymName, L"\\DosDevices\\KDRV");
  Status = IoCreateSymbolicLink(&DeviceSymName, &DeviceName);
  if (!NT_SUCCESS(Status))
  {
    LOG_ERROR("IoCreateSymbolicLink\n");
    return Status;
  }
  return Status;
}
NTSTATUS KDRV::DeInitialize(PDRIVER_OBJECT driverObject)
{
  UNREFERENCED_PARAMETER(driverObject);
  // Destroy symbolic link
  Status = IoDeleteSymbolicLink(&DeviceSymName);
  if (!NT_SUCCESS(Status))
  {
    LOG_ERROR("IoDeleteSymbolicLink\n");
    return Status;
  }
  // Destroy I/O device
  IoDeleteDevice(DeviceObject);
  return Status;
}

NTSTATUS KDRV::OnRead(PKDRV_READ_REQUEST request, PBYTE outputBuffer, PULONG written)
{
  UNREFERENCED_PARAMETER(request);
  UNREFERENCED_PARAMETER(outputBuffer);
  UNREFERENCED_PARAMETER(written);
  // Find associated process
  PEPROCESS process = NULL;
  Status = PsLookupProcessByProcessId((HANDLE)request->Pid, &process);
  if (!NT_SUCCESS(Status))
  {
    LOG_ERROR("PsLookupProcessByProcessId\n");
    return Status;
  }
  // Attach to context
  KAPC_STATE apc;
  KeStackAttachProcess(process, &apc);
  __try
  {
    // Copy virtual memory
    RtlCopyMemory(outputBuffer, request->Base, request->Size);
    *written = (ULONG)request->Size;
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    LOG_ERROR("Failed reading memory\n");
    Status = STATUS_ACCESS_DENIED;
  }
  // Detach from context
  KeUnstackDetachProcess(&apc);
  return Status;
}
NTSTATUS KDRV::OnWrite(PKDRV_WRITE_REQUEST request, PBYTE outputBuffer, PULONG written)
{
  UNREFERENCED_PARAMETER(request);
  UNREFERENCED_PARAMETER(outputBuffer);
  UNREFERENCED_PARAMETER(written);

  return Status;
}

VOID DriverUnload(PDRIVER_OBJECT driverObject)
{
  NTSTATUS status = sKdrv.DeInitialize(driverObject);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("KDRV failed while deinitializing\n");
    return;
  }
  LOG_INFO("KDRV deinitialized\n");
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
    case KDRV_CTRL_READ_REQUEST:
    {
      // Write request
      PKDRV_READ_REQUEST readRequest = (PKDRV_READ_REQUEST)irp->AssociatedIrp.SystemBuffer;
      PBYTE outputBuffer = NULL;
      if (irp->MdlAddress)
        outputBuffer = (PBYTE)MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
      if (readRequest && outputBuffer)
      {
        ULONG written = 0;
        irp->IoStatus.Status = sKdrv.OnRead(readRequest, outputBuffer, &written);
        if (NT_SUCCESS(irp->IoStatus.Status))
          irp->IoStatus.Information = sizeof(BYTE) * written;
      }
      break;
    }
    case KDRV_CTRL_WRITE_REQUEST:
    {
      // Read request
      PKDRV_WRITE_REQUEST writeRequest = (PKDRV_WRITE_REQUEST)irp->AssociatedIrp.SystemBuffer;
      PBYTE outputBuffer = NULL;
      if (irp->MdlAddress)
        outputBuffer = (PBYTE)MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
      if (writeRequest && outputBuffer)
      {
        ULONG written = 0;
        irp->IoStatus.Status = sKdrv.OnWrite(writeRequest, outputBuffer, &written);
        if (NT_SUCCESS(irp->IoStatus.Status))
          irp->IoStatus.Information = sizeof(BYTE) * written;
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

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING regPath)
{
  UNREFERENCED_PARAMETER(regPath);

  NTSTATUS status = STATUS_SUCCESS;

  // Initialize kernel driver
  status = sKdrv.Initialize(driverObject);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("KDRV failed while initializing\n");
    return status;
  }
  LOG_INFO("KDRV initialized\n");

  // Reg driver callbacks
  driverObject->DriverUnload = DriverUnload;

  // Reg default irp callbacks
  for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
    driverObject->MajorFunction[i] = OnIrpDflt;

  // Reg kdrv irp callbacks
  driverObject->MajorFunction[IRP_MJ_CREATE] = OnIrpCreate;
  driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OnIrpIoCtrl;
  driverObject->MajorFunction[IRP_MJ_CLOSE] = OnIrpClose;

  return status;
}
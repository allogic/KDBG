#include "kdrv.h"
#include "klogic.h"
#include "ulogic.h"
#include "pe.h"
#include "undoc.h"

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
    case KDRV_CTRL_READ_KERNEL_REQUEST:
    {
      // Kernel read request
      PKDRV_READ_KERNEL_REQUEST request = (PKDRV_READ_KERNEL_REQUEST)irp->AssociatedIrp.SystemBuffer;
      PBYTE outputBuffer = NULL;
      if (irp->MdlAddress)
        outputBuffer = (PBYTE)MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
      if (request && outputBuffer)
      {
        // Find image base
        PVOID imageBase = NULL;
        irp->IoStatus.Status = GetKernelImageBase(request->ImageName, &imageBase, NULL);
        if (NT_SUCCESS(irp->IoStatus.Status))
        {
          LOG_INFO("Found image %s", request->ImageName);
          // Find export base
          PVOID exportBase = RtlFindExportedRoutineByName(imageBase, request->ExportName);
          if (exportBase)
          {
            LOG_INFO("Found export %s", request->ExportName);
            // Read kernel memeory
            irp->IoStatus.Status = TryReadKernelMemory((PVOID)((ULONG_PTR)exportBase + request->Offset), outputBuffer, request->Size);
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
        irp->IoStatus.Status = GetKernelImageBase(request->ImageName, &imageBase, NULL);
        if (NT_SUCCESS(irp->IoStatus.Status))
        {
          // Find export base
          PVOID exportBase = RtlFindExportedRoutineByName(imageBase, request->ExportName);
          if (exportBase)
          {
            // Write kernel memeory
            irp->IoStatus.Status = TryWriteKernelMemory((PVOID)((ULONG_PTR)exportBase + request->Offset), request->Bytes, request->Size);
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
      PBYTE outputBuffer = NULL;
      if (irp->MdlAddress)
        outputBuffer = (PBYTE)MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
      if (request && outputBuffer)
      {
        // TODO implement me..
      }
      break;
    }
    case KDRV_CTRL_WRITE_USER_REQUEST:
    {
      // User write request
      PKDRV_WRITE_USER_REQUEST request = (PKDRV_WRITE_USER_REQUEST)irp->AssociatedIrp.SystemBuffer;
      if (request)
      {
        // TODO implement me..
      }
      break;
    }
    case KDRV_CTRL_DEBUG_REQUEST:
    {
      // Debug request
      __try
      {
        DumpKernelImages();

        PVOID dxgkrnlBase = NULL;
        ULONG dxgkrnlSize = 0;
        irp->IoStatus.Status = GetKernelImageBase("dxgkrnl.sys", &dxgkrnlBase, &dxgkrnlSize);
        if (dxgkrnlBase)
        {
          LOG_INFO("dxgkrnl.sys at %p with size %u\n", dxgkrnlBase, dxgkrnlSize);

          PVOID ntQCSSBase = RtlFindExportedRoutineByName(dxgkrnlBase, "NtQueryCompositionSurfaceStatistics");
          //ULONG ntQCSSOffset = GetExportOffset(dxgkrnlBase, dxgkrnlSize, "NtQueryCompositionSurfaceStatistics");
          LOG_INFO("NtQueryCompositionSurfaceStatistics at %p\n", ntQCSSBase);
        }

        PVOID ntoskrnlBase = NULL;
        ULONG ntosKrnlSize = 0;
        irp->IoStatus.Status = GetKernelImageBase("ntoskrnl.exe", &ntoskrnlBase, &ntosKrnlSize);
        if (ntoskrnlBase)
        {
          LOG_INFO("ntoskrnl.exe at %p with size %u\n", ntoskrnlBase, ntosKrnlSize);

          PVOID ntOPBase = RtlFindExportedRoutineByName(ntoskrnlBase, "NtOpenProcess");
          //ULONG ntOPOffset = GetExportOffset(ntoskrnlBase, ntosKrnlSize, "NtOpenProcess");
          LOG_INFO("NtOpenProcess at %p\n", ntOPBase);

          LOG_INFO("Original bytes\n");
          PUCHAR readBufferA = (PUCHAR)RtlAllocateMemory(TRUE, 8);
          irp->IoStatus.Status = TryReadKernelMemory(ntOPBase, readBufferA, 8);
          for (SIZE_T i = 0; i < 8; i++)
            LOG_INFO("Byte %02X\n", readBufferA[i]);
          RtlFreeMemory(readBufferA);

          //LOG_INFO("Writing bytes\n");
          //PUCHAR patchBuffer = (PUCHAR)RtlAllocateMemory(TRUE, 8);
          //RtlFillMemory(patchBuffer, 8, 0x90);
          //irp->IoStatus.Status = TryWriteKernelMemory(ntOPBase, patchBuffer, 8);
          //RtlFreeMemory(patchBuffer);

          //LOG_INFO("Altered bytes\n");
          //PUCHAR readBufferB = (PUCHAR)RtlAllocateMemory(TRUE, 8);
          //irp->IoStatus.Status = TryReadKernelMemory(ntOPBase, readBufferB, 8);
          //for (SIZE_T i = 0; i < 8; i++)
          //  LOG_INFO("Byte %02X\n", readBufferB[i]);
          //RtlFreeMemory(readBufferB);
        }
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
  NTSTATUS status = sKdrv.DeInitialize(driverObject);
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
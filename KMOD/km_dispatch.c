#include <km_dispatch.h>
#include <km_debug.h>
#include <km_memory.h>
#include <km_process_image.h>
#include <km_kernel_image.h>
#include <km_scanner.h>

///////////////////////////////////////////////////////////
// IRP handlers
///////////////////////////////////////////////////////////

NTSTATUS
KmOnIrpDflt(
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
KmOnIrpCreate(
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
KmOnIrpCtrl(
  PDEVICE_OBJECT device,
  PIRP irp)
{
  UNREFERENCED_PARAMETER(device);
  PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
  switch (stack->Parameters.DeviceIoControl.IoControlCode)
  {
    // Update API
    case IOCTRL_UPDATE_PROCESS_IMAGES:
    {
      DWORD32 pid = *(PDWORD32)irp->AssociatedIrp.SystemBuffer;
      PDWORD32 count = (PDWORD32)irp->AssociatedIrp.SystemBuffer;
      irp->IoStatus.Status = KmUpdateProcessImages(pid, count);
      irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? sizeof(DWORD32) : 0;
      KD_LOG("[IOCTRL_UPDATE_PROCESS_IMAGES] status:%X written:%llu\n", irp->IoStatus.Status, irp->IoStatus.Information);
      break;
    }
    case IOCTRL_UPDATE_KERNEL_IMAGES:
    {
      PDWORD32 count = (PDWORD32)irp->AssociatedIrp.SystemBuffer;
      irp->IoStatus.Status = KmUpdateKernelImages(count);
      irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? sizeof(DWORD32) : 0;
      KD_LOG("[IOCTRL_UPDATE_KERNEL_IMAGES] status:%X written:%llu\n", irp->IoStatus.Status, irp->IoStatus.Information);
      break;
    }
    // Read API
    case IOCTRL_READ_PROCESS_IMAGES:
    {
      DWORD32 count = *(PDWORD32)irp->AssociatedIrp.SystemBuffer;
      PPROCESS_IMAGE images = (PPROCESS_IMAGE)irp->AssociatedIrp.SystemBuffer;
      irp->IoStatus.Status = KmReadProcessImageList(count, images);
      irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? (sizeof(PROCESS_IMAGE) * count) : 0;
      KD_LOG("[IOCTRL_READ_PROCESS_IMAGES] status:%X written:%llu\n", irp->IoStatus.Status, irp->IoStatus.Information);
      break;
    }
    case IOCTRL_READ_KERNEL_IMAGES:
    {
      DWORD32 count = *(PDWORD32)irp->AssociatedIrp.SystemBuffer;
      PKERNEL_IMAGE images = (PKERNEL_IMAGE)irp->AssociatedIrp.SystemBuffer;
      irp->IoStatus.Status = KmReadKernelImageList(count, images);
      irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? (sizeof(KERNEL_IMAGE) * count) : 0;
      KD_LOG("[IOCTRL_READ_KERNEL_IMAGES] status:%X written:%llu\n", irp->IoStatus.Status, irp->IoStatus.Information);
      break;
    }
    case IOCTRL_READ_PROCESS_MEMORY:
    {
      READ_PROCESS_MEMORY request = *(PREAD_PROCESS_MEMORY)irp->AssociatedIrp.SystemBuffer;
      PBYTE bytes = (PBYTE)irp->AssociatedIrp.SystemBuffer;
      irp->IoStatus.Status = KmReadProcessMemory(&request, bytes);
      irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? request.Size : 0;
      KD_LOG("[IOCTRL_READ_PROCESS_MEMORY] status:%X written:%llu\n", irp->IoStatus.Status, irp->IoStatus.Information);
      break;
    }
    case IOCTRL_READ_KERNEL_MEMORY:
    {
      READ_KERNEL_MEMORY request = *(PREAD_KERNEL_MEMORY)irp->AssociatedIrp.SystemBuffer;
      PBYTE bytes = (PBYTE)irp->AssociatedIrp.SystemBuffer;
      irp->IoStatus.Status = KmReadKernelMemory(&request, bytes);
      irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? request.Size : 0;
      KD_LOG("[IOCTRL_READ_KERNEL_MEMORY] status:%X written:%llu\n", irp->IoStatus.Status, irp->IoStatus.Information);
      break;
    }
    case IOCTRL_READ_SCAN_RESULTS:
    {
      DWORD32 count = *(PDWORD32)irp->AssociatedIrp.SystemBuffer;
      PDWORD64 scans = (PDWORD64)irp->AssociatedIrp.SystemBuffer;
      irp->IoStatus.Status = KmReadScanList(count, scans);
      irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? (sizeof(DWORD64) * count) : 0;
      KD_LOG("[IOCTRL_READ_SCAN_RESULTS] status:%X written:%llu\n", irp->IoStatus.Status, irp->IoStatus.Information);
      break;
    }
    // Write API
    case IOCTRL_WRITE_PROCESS_MEMORY:
    {
      WRITE_PROCESS_MEMORY request = *(PWRITE_PROCESS_MEMORY)irp->AssociatedIrp.SystemBuffer;
      irp->IoStatus.Status = KmWriteProcessMemory(&request);
      irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? 0 : 0;
      KD_LOG("[IOCTRL_WRITE_PROCESS_MEMORY] status:%X written:%llu\n", irp->IoStatus.Status, irp->IoStatus.Information);
      break;
    }
    case IOCTRL_WRITE_KERNEL_MEMORY:
    {
      WRITE_KERNEL_MEMORY request = *(PWRITE_KERNEL_MEMORY)irp->AssociatedIrp.SystemBuffer;
      irp->IoStatus.Status = KmWriteKernelMemory(&request);
      irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? 0 : 0;
      KD_LOG("[IOCTRL_WRITE_KERNEL_MEMORY] status:%X written:%llu\n", irp->IoStatus.Status, irp->IoStatus.Information);
      break;
    }
    // Scan API
    case IOCTRL_SCAN_PROCESS_FIRST:
    {
      SCAN_PROCESS_FIRST request = *(PSCAN_PROCESS_FIRST)irp->AssociatedIrp.SystemBuffer;
      PDWORD32 count = (PDWORD32)irp->AssociatedIrp.SystemBuffer;
      irp->IoStatus.Status = KmScanProcessFirst(&request, count);
      irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? sizeof(DWORD32) : 0;
      KD_LOG("[IOCTRL_SCAN_PROCESS_FIRST] status:%X written:%llu\n", irp->IoStatus.Status, irp->IoStatus.Information);
      break;
    }
    case IOCTRL_SCAN_PROCESS_NEXT:
    {
      SCAN_PROCESS_NEXT request = *(PSCAN_PROCESS_NEXT)irp->AssociatedIrp.SystemBuffer;
      irp->IoStatus.Status = KmScanProcessNext(&request);
      irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? 0 : 0;
      KD_LOG("[IOCTRL_SCAN_PROCESS_NEXT] status:%X written:%llu\n", irp->IoStatus.Status, irp->IoStatus.Information);
      break;
    }
  }
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return irp->IoStatus.Status;
}

NTSTATUS
KmOnIrpClose(
  PDEVICE_OBJECT device,
  PIRP irp)
{
  UNREFERENCED_PARAMETER(device);
  irp->IoStatus.Status = STATUS_SUCCESS;
  irp->IoStatus.Information = 0;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return irp->IoStatus.Status;
}
#include <km_core.h>
#include <km_debug.h>
#include <km_dispatch.h>
#include <km_process_image.h>
#include <km_kernel_image.h>
#include <km_scanner.h>

///////////////////////////////////////////////////////////
// Locals
///////////////////////////////////////////////////////////

static PDEVICE_OBJECT s_deviceHandle = NULL;

///////////////////////////////////////////////////////////
// Entry point
///////////////////////////////////////////////////////////

VOID
DriverUnload(
  PDRIVER_OBJECT driver)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;

  UNREFERENCED_PARAMETER(driver);

  // Destroy communication device
  UNICODE_STRING symbolName = RTL_CONSTANT_STRING(L"\\DosDevices\\KMOD");
  status = IoDeleteSymbolicLink(&symbolName);
  if (NT_SUCCESS(status))
  {
    IoDeleteDevice(s_deviceHandle);
  }

  // Free lists
  status = KmResetKernelImageList();
  status = KmResetProcessImageList();
  status = KmResetScanList();

  // Check driver unload successfully
  if (NT_SUCCESS(status))
  {
    KD_LOG("KMOD deinitialized\n");
  }
}


NTSTATUS
DriverEntry(
  PDRIVER_OBJECT driver,
  PUNICODE_STRING regPath)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;

  UNREFERENCED_PARAMETER(regPath);

  // Setup driver unload procedure
  driver->DriverUnload = DriverUnload;

  // Setup irp handlers
  for (DWORD32 i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
  {
    driver->MajorFunction[i] = KmOnIrpDflt;
  }
  driver->MajorFunction[IRP_MJ_CREATE] = KmOnIrpCreate;
  driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KmOnIrpCtrl;
  driver->MajorFunction[IRP_MJ_CLOSE] = KmOnIrpClose;

  // Create communication device
  UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\KMOD");
  UNICODE_STRING symbolName = RTL_CONSTANT_STRING(L"\\DosDevices\\KMOD");
  status = IoCreateDevice(driver, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, 0, &s_deviceHandle);
  if (NT_SUCCESS(status))
  {
    s_deviceHandle->Flags &= ~DO_DEVICE_INITIALIZING;
    IoCreateSymbolicLink(&symbolName, &deviceName);
  }

  // Initialize lists
  status = KmInitializeProcessImageList();
  status = KmInitializeKernelImageList();
  status = KmInitializeScanList();

  // Check driver load successfully
  if (NT_SUCCESS(status))
  {
    KD_LOG("KMOD initialized\n");
  }

  return status;
}
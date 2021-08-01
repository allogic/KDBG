#include "device.h"

NTSTATUS
CreateDevice(
  PDRIVER_OBJECT driver,
  PDEVICE_OBJECT& device,
  PCWCHAR deviceName,
  PCWCHAR symbolicName)
{
  NTSTATUS status = STATUS_SUCCESS;
  UNICODE_STRING deviceNameTmp;
  UNICODE_STRING symbolicNameTmp;
  RtlInitUnicodeString(&deviceNameTmp, deviceName);
  RtlInitUnicodeString(&symbolicNameTmp, symbolicName);
  status = IoCreateDevice(driver, 0, &deviceNameTmp, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, 0, &device);
  if (NT_SUCCESS(status))
  {
    device->Flags |= (DO_DIRECT_IO | DO_BUFFERED_IO);
    device->Flags &= ~DO_DEVICE_INITIALIZING;
    IoCreateSymbolicLink(&symbolicNameTmp, &deviceNameTmp);
  }
  return status;
}

NTSTATUS
DeleteDevice(
  PDEVICE_OBJECT device,
  PCWCHAR symbolicName)
{
  NTSTATUS status = STATUS_SUCCESS;
  UNICODE_STRING symbolicNameTmp;
  RtlInitUnicodeString(&symbolicNameTmp, symbolicName);
  status = IoDeleteSymbolicLink(&symbolicNameTmp);
  if (NT_SUCCESS(status))
  {
    IoDeleteDevice(device);
  }
  return status;
}
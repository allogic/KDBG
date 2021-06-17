#include "device.h"

NTSTATUS CreateDevice(PDRIVER_OBJECT driver, PDEVICE_OBJECT& device, PUNICODE_STRING deviceName, PUNICODE_STRING symbolicName)
{
  NTSTATUS status = STATUS_SUCCESS;
  // Create I/O device
  status = IoCreateDevice(driver, 0, deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, 0, &device);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("IoCreateDevice\n");
    return status;
  }
  device->Flags |= (DO_DIRECT_IO | DO_BUFFERED_IO);
  device->Flags &= ~DO_DEVICE_INITIALIZING;
  // Create symbolic link
  status = IoCreateSymbolicLink(symbolicName, deviceName);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("IoCreateSymbolicLink\n");
    return status;
  }
  return status;
}
NTSTATUS DeleteDevice(PDEVICE_OBJECT device, PUNICODE_STRING symbolicName)
{
  NTSTATUS status = STATUS_SUCCESS;
  // Delete symbolic link
  status = IoDeleteSymbolicLink(symbolicName);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("IoDeleteSymbolicLink\n");
    return status;
  }
  // Delete I/O device
  IoDeleteDevice(device);
  return status;
}
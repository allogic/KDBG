#include "kdrv.h"
#include "mem.h"
#include "pe.h"
#include "undoc.h"
#include "device.h"
#include "session.h"

// Global device/symbol names
#define KDRV_CMD_DEVICE_NAME L"\\Device\\KdrvCmd"
#define KDRV_KERNEL_DEVICE_NAME L"\\Device\\KdrvKernel"
#define KDRV_USER_DEVICE_NAME L"\\Device\\KdrvUser"

#define KDRV_CMD_DEVICE_SYMBOL_NAME L"\\DosDevices\\KdrvCmd"
#define KDRV_KERNEL_DEVICE_SYMBOL_NAME L"\\DosDevices\\KdrvKernel"
#define KDRV_USER_DEVICE_SYMBOL_NAME L"\\DosDevices\\KdrvUser"

// Global cmd device
PDEVICE_OBJECT CmdDevice = NULL;

// Global sessions
PKDRV_KERNEL_SESSION KernelSession = NULL;
PKDRV_USER_SESSION UserSession = NULL;

VOID KernelSessionThread(PVOID context)
{
  UNREFERENCED_PARAMETER(context);
  UINT i = 0;
  while (i < 10)
  {
    LOG_INFO("Kernel session thread called %u\n", i);
    DriverSleep(5000);
    ++i;
  }
}
VOID UserSessionThread(PVOID context)
{
  UNREFERENCED_PARAMETER(context);
  UINT i = 0;
  while (i < 10)
  {
    LOG_INFO("User session thread called %u\n", i);
    DriverSleep(2500);
    ++i;
  }
}

NTSTATUS InitializeSessions(PDRIVER_OBJECT driver)
{
  NTSTATUS status = STATUS_SUCCESS;
  // Create kernel/user session threads
  KernelSession = (PKDRV_KERNEL_SESSION)RtlAllocateMemory(TRUE, sizeof(KDRV_KERNEL_SESSION));
  status = PsCreateSystemThread(&KernelSession->Thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, KernelSessionThread, NULL);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("Failed creating kernel session thread\n");
    return status;
  }
  UserSession = (PKDRV_USER_SESSION)RtlAllocateMemory(TRUE, sizeof(KDRV_USER_SESSION));
  status = PsCreateSystemThread(&UserSession->Thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, UserSessionThread, NULL);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("Failed creating user session thread\n");
    return status;
  }
  // Create kernel device
  UNICODE_STRING deviceName;
  UNICODE_STRING symbolicName;
  RtlInitUnicodeString(&deviceName, KDRV_KERNEL_DEVICE_NAME);
  RtlInitUnicodeString(&symbolicName, KDRV_KERNEL_DEVICE_SYMBOL_NAME);
  status = CreateDevice(driver, KernelSession->Device, &deviceName, &symbolicName);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("CreateDevice\n");
    return status;
  }
  // Create user device
  RtlInitUnicodeString(&deviceName, KDRV_USER_DEVICE_NAME);
  RtlInitUnicodeString(&symbolicName, KDRV_USER_DEVICE_SYMBOL_NAME);
  status = CreateDevice(driver, UserSession->Device, &deviceName, &symbolicName);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("CreateDevice\n");
    return status;
  }
  return status;
}
NTSTATUS DeInitializeSessions(PDRIVER_OBJECT driver)
{
  UNREFERENCED_PARAMETER(driver);
  NTSTATUS status = STATUS_SUCCESS;
  // Delete kernel/user session threads
  RtlFreeMemory(KernelSession);
  status = ZwClose(KernelSession->Thread);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("Failed closing kernel session\n");
    return status;
  }
  RtlFreeMemory(UserSession);
  status = ZwClose(UserSession->Thread);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("Failed closing user session\n");
    return status;
  }
  return status;
}

NTSTATUS Initialize(PDRIVER_OBJECT driver)
{
  NTSTATUS status = STATUS_SUCCESS;
  // Create cmd device
  UNICODE_STRING deviceName;
  UNICODE_STRING symbolicName;
  RtlInitUnicodeString(&deviceName, KDRV_CMD_DEVICE_NAME);
  RtlInitUnicodeString(&symbolicName, KDRV_CMD_DEVICE_SYMBOL_NAME);
  status = CreateDevice(driver, CmdDevice, &deviceName, &symbolicName);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("CreateDevice\n");
    return status;
  }
  // Create sessions
  status = InitializeSessions(driver);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("InitializeSessions\n");
    return status;
  }
  return status;
}
NTSTATUS DeInitialize(PDRIVER_OBJECT driver)
{
  UNREFERENCED_PARAMETER(driver);
  NTSTATUS status = STATUS_SUCCESS;
  // Delete sessions
  status = DeInitializeSessions(driver);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("DeInitializeSessions\n");
    return status;
  }
  // Delete cmd device
  UNICODE_STRING symbolicName;
  RtlInitUnicodeString(&symbolicName, KDRV_CMD_DEVICE_SYMBOL_NAME);
  status = DeleteDevice(CmdDevice, &symbolicName);
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
  switch (stack->Parameters.DeviceIoControl.IoControlCode)
  {    
    case KDRV_CTRL_SESSION:
    {
      __try
      {
        //PKDRV_SESSION_REQEUST request = (PKDRV_SESSION_REQEUST)irp->AssociatedIrp.SystemBuffer;
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
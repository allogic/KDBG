#include "global.h"

#define KMOD_DEVICE_NAME "\\\\.\\KMOD"

#define KMOD_EXEC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0100, METHOD_OUT_DIRECT, FILE_SPECIAL_ACCESS)

INT main(INT argc, PCHAR argv[])
{
  // Connect to driver
  HANDLE Device = CreateFileA(KMOD_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
  if (Device == INVALID_HANDLE_VALUE)
  {
    LOG_ERROR("Device connection cannot be established\n");
  }
  else
  {
    // Issue commands
    if (strcmp(argv[1], "/Exec") == 0)
    {
      ULONG tid = strtoul(argv[2], NULL, 10);
      if (DeviceIoControl(Device, KMOD_EXEC, &tid, sizeof(tid), &tid, sizeof(tid), NULL, NULL))
      {
        LOG_INFO("Success\n");
      }
    }
    // Cleanup
    CloseHandle(Device);
  }
  return 0;
}
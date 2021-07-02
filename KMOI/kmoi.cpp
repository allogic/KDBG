#include "global.h"

#define KMOD_DEVICE_NAME "\\\\.\\KMOD"

#define KMOD_EXEC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0666, METHOD_OUT_DIRECT, FILE_SPECIAL_ACCESS)

INT main(INT argc, PCHAR argv[])
{
  // Connect to driver
  HANDLE Device = CreateFileA(KMOD_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
  if (Device)
  {
    // Issue commands
    if (strcmp(argv[1], "/Exec") == 0)
    {
      PBYTE req = (PBYTE)argv[2];
      if (DeviceIoControl(Device, KMOD_EXEC, &req, sizeof(req), NULL, NULL, NULL, NULL))
      {
        LOG_INFO("Success\n");
      }
    }
    // Cleanup
    CloseHandle(Device);
  }
  return 0;
}
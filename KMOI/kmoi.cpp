#include "global.h"

#define KMOD_EXEC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0666, METHOD_OUT_DIRECT, FILE_SPECIAL_ACCESS)

HANDLE Device = NULL;

INT main(INT argc, PCHAR argv[])
{
  // Optain communication device
  Device = CreateFileA("\\\\.\\KDRV", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
  if (Device == INVALID_HANDLE_VALUE)
  {
    LOG_INFO("KDRV link failed\n");
    return 1;
  }
  // Issue commands
  if (strcmp(argv[1], "/Exec") == 0)
  {
    PBYTE req = (PBYTE)argv[2];
    if (DeviceIoControl(Device, KMOD_EXEC, &req, sizeof(req), NULL, NULL, NULL, NULL))
    {
      LOG_INFO("Success\n");
    }
  }
  return 0;
}
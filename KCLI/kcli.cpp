#include "global.h"
#include "common.h"
#include "ioctrl.h"
#include "util.h"

/*
* I/O communication device.
*/

#define KC_DEVICE_NAME "\\\\.\\KMOD"

HANDLE Device = NULL;

/*
* Entry point.
*/

INT
wmain(
  INT argc,
  PWCHAR argv[])
{
  //Device = CreateFileA(KC_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
  //if (Device != NULL)
  //{
    if (_wcsicmp(L"/wmp", argv[1]) == 0)
    {
      WRITE_MEMORY_PROCESS request = {};
      request.Pid = GetProcessIdFromNameW(argv[2]);
      wcscpy_s(request.ImageName, argv[3]);
      request.Offset = wcstoul(argv[4], NULL, 10);
      request.Size = wcstoul(argv[5], NULL, 10);
      HexToBytesW(request.Bytes, argv[6]);
      KC_LOG_INFO("Pid %u\n", request.Pid);
      KC_LOG_INFO("ImageName %ls\n", request.ImageName);
      KC_LOG_INFO("Offset %u\n", request.Offset);
      KC_LOG_INFO("Size %u\n", request.Size);
      for (ULONG i = 0; i < request.Size; ++i)
      {
        KC_LOG_INFO("Bytes %02X\n", request.Bytes[i]);
      }
      if (DeviceIoControl(Device, KM_WRITE_MEMORY_PROCESS, &request, sizeof(request), 0, 0, 0, 0))
      {
        KC_LOG_INFO("Success\n");
      }
    }
    else if (_wcsicmp(L"/wmk", argv[1]) == 0)
    {
      WRITE_MEMORY_KERNEL request = {};
      wcscpy_s(request.ImageName, argv[2]);
      request.Offset = wcstoul(argv[3], NULL, 10);
      request.Size = wcstoul(argv[4], NULL, 10);
      HexToBytesW(request.Bytes, argv[5]);
      KC_LOG_INFO("ImageName %ls\n", request.ImageName);
      KC_LOG_INFO("Offset %u\n", request.Offset);
      KC_LOG_INFO("Size %u\n", request.Size);
      for (ULONG i = 0; i < request.Size; ++i)
      {
        KC_LOG_INFO("Bytes %02X\n", request.Bytes[i]);
      }
      if (DeviceIoControl(Device, KM_WRITE_MEMORY_KERNEL, &request, sizeof(request), 0, 0, 0, 0))
      {
        KC_LOG_INFO("Success\n");
      }
    }
  //}
  return 0;
}
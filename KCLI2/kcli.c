#include "global.h"
#include "ioctrl.h"

/*
* I/O communication device
*/

#define KC_DEVICE_NAME "\\\\.\\KMOD2"

HANDLE Device = NULL;

/*
* Entry point.
*/

INT
wmain(
  INT argc,
  PWCHAR argv[])
{
  Device = CreateFileA(KC_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
  if (Device != NULL)
  {
    // Debug
    if (_wcsicmp(L"/Debug", argv[1]) == 0)
    {
      if (DeviceIoControl(Device, KC_CTRL_DEBUG, 0, 0, 0, 0, 0, 0))
      {
        printf("Success\n");
      }
      else
      {
        printf("Failure\n");
      }
      printf("\n");
    }
    // Cleanup
    CloseHandle(Device);
  }
  return 0;
}
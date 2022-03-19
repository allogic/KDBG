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
  __try
  {
    //
    // Triggers Divide-By-Zero exception
    //
  
    volatile int A = 1;
    volatile int B = 0;
    volatile int C = A / B;
  
    (void)C;
  }
  __except (GetExceptionCode() == EXCEPTION_INT_DIVIDE_BY_ZERO ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
  {
  }
  
  return 0;
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
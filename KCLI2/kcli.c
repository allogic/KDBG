#include "global.h"
#include "ioctrl.h"

/*
* I/O communication device
*/

#define KC_DEVICE_NAME "\\\\.\\KMOD2"

HANDLE Device = NULL;

typedef struct _STACK
{
  LWORD ThreadId;
  LWORD RFlags;
  LWORD RAX;
  LWORD RBX;
  LWORD RCX;
  LWORD RDX;
  LWORD RSI;
  LWORD RDI;
  LWORD RBP;
  LWORD RSP;
  LWORD RIP;
  LWORD R8;
  LWORD R9;
  LWORD R10;
  LWORD R11;
  LWORD R12;
  LWORD R13;
  LWORD R14;
  LWORD R15;
  LWORD CS;
  LWORD DS;
  LWORD ES;
  LWORD FS;
  LWORD GS;
  LWORD SS;
  LWORD DR0;
  LWORD DR1;
  LWORD DR2;
  LWORD DR3;
  LWORD DR6;
  LWORD DR7;
  BYTE FxState[512];
  LWORD LBRCount;
  LWORD LBR[16];
} STACK, * PSTACK;

/*
* Entry point.
*/

INT
wmain(
  INT argc,
  PWCHAR argv[])
{
  printf("%llu\n", sizeof(STACK));
  //__try
  //{
  //  //
  //  // Triggers Divide-By-Zero exception
  //  //
  //
  //  volatile int A = 1;
  //  volatile int B = 0;
  //  volatile int C = A / B;
  //
  //  (void)C;
  //}
  //__except (GetExceptionCode() == EXCEPTION_INT_DIVIDE_BY_ZERO ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
  //{
  //}
  //
  //return 0;
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
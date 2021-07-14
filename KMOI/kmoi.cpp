#include "global.h"

/*
* I/O communication.
*/

#define KMOD_REQ_SCAN_INT_SIGNED CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0100, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define KMOD_REQ_SCAN_CONTEXT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0101, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define KMOD_REQ_SCAN_STACK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0102, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _REQ_SCAN_INT_SIGNED
{
  ULONG Pid;
  PWCHAR Name;
  ULONG Offset;
  SIZE_T Size;
  INT Value;
} REQ_SCAN_INT_SIGNED, * PREQ_SCAN_INT_SIGNED;
typedef struct _REQ_SCAN_CONTEXT
{
  ULONG Tid;
  ULONG Iterations; // Change to TIME_T
} REQ_SCAN_CONTEXT, * PREQ_SCAN_CONTEXT;
typedef struct _REQ_SCAN_STACK
{
  ULONG Tid;
  ULONG Iterations; // Change to TIME_T
} REQ_SCAN_STACK, * PREQ_SCAN_STACK;

/*
* Communication device.
*/

#define KMOD_DEVICE_NAME "\\\\.\\KMOD"

/*
* Wide character utilities.
*/

SIZE_T ArgvLength(PWCHAR argv)
{
  SIZE_T length = 0;
  while (*(argv++))
    ++length;
  return ++length;
}

/*
* Entry point.
*/

INT wmain(INT argc, PWCHAR argv[])
{
  // Connect to driver
  HANDLE Device = CreateFileA(KMOD_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
  if (Device == INVALID_HANDLE_VALUE)
  {
    LOG_ERROR("Device connection cannot be established\n");
  }
  else
  {
    // Scan int signed
    if (wcscmp(L"/Sis", argv[1]) == 0)
    {
      REQ_SCAN_INT_SIGNED req;
      req.Pid = wcstoul(argv[2], NULL, 10);
      req.Name = (PWCHAR)malloc(sizeof(WCHAR) * ArgvLength(argv[3]));
      memcpy(req.Name, argv[3], sizeof(WCHAR) * ArgvLength(argv[3]));
      req.Offset = wcstoul(argv[4], NULL, 10);
      req.Size = wcstoul(argv[5], NULL, 10);
      req.Value = wcstoul(argv[6], NULL, 10);
      if (DeviceIoControl(Device, KMOD_REQ_SCAN_INT_SIGNED, &req, sizeof(req), &req, sizeof(req), NULL, NULL))
      {
        LOG_INFO("Success\n");
      }
      free(req.Name);
    }
    // Scan context
    if (wcscmp(L"/Sc", argv[1]) == 0)
    {
      REQ_SCAN_CONTEXT req;
      req.Tid = wcstoul(argv[2], NULL, 10);
      req.Iterations = wcstoul(argv[3], NULL, 10);
      if (DeviceIoControl(Device, KMOD_REQ_SCAN_INT_SIGNED, &req, sizeof(req), &req, sizeof(req), NULL, NULL))
      {
        LOG_INFO("Success\n");
      }
    }
    // Scan stack
    if (wcscmp(L"/Ss", argv[1]) == 0)
    {
      REQ_SCAN_STACK req;
      req.Tid = wcstoul(argv[2], NULL, 10);
      req.Iterations = wcstoul(argv[3], NULL, 10);
      if (DeviceIoControl(Device, KMOD_REQ_SCAN_INT_SIGNED, &req, sizeof(req), &req, sizeof(req), NULL, NULL))
      {
        LOG_INFO("Success\n");
      }
    }
    // Cleanup
    CloseHandle(Device);
  }
  return 0;
}
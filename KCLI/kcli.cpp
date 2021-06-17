#include "kcli.h"
#include "util.h"

HANDLE CmdDevice = INVALID_HANDLE_VALUE;
HANDLE KernelDevice = INVALID_HANDLE_VALUE;
HANDLE UserDevice = INVALID_HANDLE_VALUE;

INT Initialize()
{
  // Optain communication devices
  CmdDevice = CreateFileA("\\\\.\\KdrvCmd", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
  KernelDevice = CreateFileA("\\\\.\\KdrvKernel", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
  UserDevice = CreateFileA("\\\\.\\KdrvUser", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
  if (CmdDevice == INVALID_HANDLE_VALUE || KernelDevice == INVALID_HANDLE_VALUE || UserDevice == INVALID_HANDLE_VALUE)
  {
    std::printf("KDRV is not running properly\n");
    return 1;
  }
  return 0;
}
INT DeInitialize()
{
  // Close communication devices
  if (!CloseHandle(CmdDevice))
    return 1;
  if (!CloseHandle(KernelDevice))
    return 1;
  if (!CloseHandle(UserDevice))
    return 1;
  return 0;
}

INT PollKernel(ULONG pollRate, ULONG bufferSize, ULONG blockSize, ULONG offset)
{
  INT status = 0;
  PBYTE bytes = AllocMemory<BYTE>(TRUE, bufferSize);
  while (1)
  {
    if (DeviceIoControl(KernelDevice, KDRV_CTRL_SESSION, &bytes, sizeof(bytes), NULL, 0, NULL, NULL))
    {
      for (ULONG i = 0; i < bufferSize; ++i)
      {
        std::printf("%02X ", bytes[i]);
        if (i != 0 && (i + 1) < bufferSize && (i + 1) % blockSize == 0)
          std::printf("\n0x%08X ", offset + (ULONG)i);
      }
      std::printf("\n\n");
      DisassembleBytes(bytes, bufferSize, offset);
      Sleep(250);
    }
    else
    {
      std::printf("Failed polling kernel bytes\n");
      status = 1;
      break;
    }
  }
  FreeMemory(bytes);
  return status;
}
INT PollUser(ULONG pollRate, ULONG bufferSize, ULONG blockSize, ULONG offset)
{
  INT status = 0;
  PBYTE bytes = AllocMemory<BYTE>(TRUE, bufferSize);
  while (1)
  {
    if (DeviceIoControl(UserDevice, KDRV_CTRL_SESSION, &bytes, sizeof(bytes), NULL, 0, NULL, NULL))
    {
      for (ULONG i = 0; i < bufferSize; ++i)
      {
        std::printf("%02X ", bytes[i]);
        if (i != 0 && (i + 1) < bufferSize && (i + 1) % blockSize == 0)
          std::printf("\n0x%08X ", offset + (ULONG)i);
      }
      std::printf("\n\n");
      DisassembleBytes(bytes, bufferSize, offset);
      Sleep(pollRate);
    }
    else
    {
      std::printf("Failed polling user bytes\n");
      status = 1;
      break;
    }
  }
  FreeMemory(bytes);
  return status;
}

INT wmain(INT argc, PWCHAR argv[])
{
  INT status = 0;
  // Initialize
  status = Initialize();
  if (status)
  {
    std::printf("Initialize\n");
    return status;
  }
  // Attach to kernel
  if (std::wcscmp(argv[1], L"/AttachKernel") == 0)
  {
    KDRV_SESSION_REQEUST request;
    if (DeviceIoControl(CmdDevice, KDRV_CTRL_SESSION, &request, sizeof(request), NULL, 0, NULL, NULL))
    {
      PollKernel(250, 64, 32, 0);
    }
  }
  // Attach to user
  if (std::wcscmp(argv[1], L"/AttachUser") == 0)
  {
    KDRV_SESSION_REQEUST request;
    if (DeviceIoControl(CmdDevice, KDRV_CTRL_SESSION, &request, sizeof(request), NULL, 0, NULL, NULL))
    {
      PollUser(250, 64, 32, 0);
    }
  }
  // DeInitialize
  status = DeInitialize();
  if (status)
  {
    std::printf("DeInitialize\n");
    return status;
  }
  return status;
}
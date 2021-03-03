#include "kcli.h"

// bcdedit /set testsigning on
// bcdedit /set nointegritychecks on
// bcdedit /debug on

// sc.exe create KCLI binPath="*.sys" type=kernel

// copy kdnet.exe VerifiedNICList.xml
// kdnet.exe <HOST-IP> <PORT>
// windbg -k net:port=50954,key=383hvuxoesn3o.3p2a8necf4mb8.399q3owp0kuel.3p4c2qi1n7v5w

// kdu.exe -dsu 0/6
// TitanHideCLI.exe ?

int main(int argc, char* argv[])
{
  DWORD written;
  HANDLE device = NULL;

  // Optain device handle
  device = CreateFileA("\\\\.\\KDRV", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);

  if (device == INVALID_HANDLE_VALUE)
  {
    printf("KDRV is not running\n");
    return 0;
  }

  // Send target request
  if (strcmp(argv[1], "/Target") == 0)
  {
    KDRV_TARGET_REQUEST request;
    request.Pid = strtoul(argv[2], NULL, 10);
    request.Base = (PVOID)strtoull(argv[3], NULL, 16);
    request.Size = strtoull(argv[4], NULL, 10);

    if (DeviceIoControl(device, KDRV_CTRL_TARGET_REQUEST, &request, sizeof(request), &request, sizeof(request), &written, NULL))
    {
      printf("Target set to pid %lu base %p size %llu\n", request.Pid, request.Base, request.Size);
    }
  }

  // Send read request
  if (strcmp(argv[1], "/Read") == 0)
  {
    SIZE_T size = strtoull(argv[2], NULL, 10);
    PBYTE request = (PBYTE)malloc(sizeof(BYTE) * size);

    memset(request, 0, size);

    if (DeviceIoControl(device, KDRV_CTRL_READ_REQUEST, &request, sizeof(request), &request, sizeof(request), &written, NULL))
    {
      printf("Read interrupt issued successfully\n");
      for (SIZE_T i = 0; i < size; i++)
        printf("%02X ", request[i]);
      printf("\n");
    }
  }

  // Send write request
  if (strcmp(argv[1], "/Write") == 0)
  {
    SIZE_T size = strtoull(argv[2], NULL, 10);
    PBYTE request = (PBYTE)malloc(sizeof(BYTE) * size);

    memset(request, 0, size);

    if (DeviceIoControl(device, KDRV_CTRL_WRITE_REQUEST, &request, sizeof(request), &request, sizeof(request), &written, NULL))
    {
      printf("Write interrupt issued successfully\n");
      for (SIZE_T i = 0; i < size; i++)
        printf("%0X ", request[i]);
      printf("\n");
    }
  }

  CloseHandle(device);

  return 0;
}
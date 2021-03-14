#include "kcli.h"
#include "util.h"

INT wmain(INT argc, PWCHAR argv[])
{
  HANDLE device = NULL;

  // Optain device handle
  device = CreateFileA("\\\\.\\KDRV", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
  if (device == INVALID_HANDLE_VALUE)
  {
    printf("KDRV is not running\n");
    return 0;
  }

  // Send dump kernel images
  if (wcscmp(argv[1], L"/DumpKernelImages") == 0)
  {
    KDRV_DUMP_KERNEL_IMAGE_REQUEST request;
    request.Size = 1024 * 1024;
    request.Images = AllocMemory<RTL_PROCESS_MODULES>(TRUE, request.Size);

    if (DeviceIoControl(device, KDRV_CTRL_DUMP_KERNEL_IMAGE_REQUEST, &request, sizeof(request), NULL, 0, NULL, NULL))
    {
      for (SIZE_T i = 0; i < request.Images->NumberOfModules; ++i)
        printf("%p %s\n", request.Images->Modules[i].ImageBase, request.Images->Modules[i].FullPathName);
    }

    FreeMemory(request.Images);
  }

  // Send dump user images
  if (wcscmp(argv[1], L"/DumpUserImages") == 0)
  {
    KDRV_DUMP_USER_IMAGE_REQUEST request;
    request.Size = 1024 * 1024;
    request.Images = AllocMemory<SYSTEM_PROCESS_INFORMATION>(TRUE, request.Size);

    if (DeviceIoControl(device, KDRV_CTRL_DUMP_USER_IMAGE_REQUEST, &request, sizeof(request), NULL, 0, NULL, NULL))
    {
      for (SIZE_T i = 0; i < request.Size; ++i)
        if ((ULONG_PTR)request.Images[i].UniqueProcessId > 0 && (ULONG_PTR)request.Images[i].UniqueProcessId < ULONG_MAX)
          printf("%llu %ws\n", (ULONG_PTR)request.Images[i].UniqueProcessId, request.Images[i].ImageName.Buffer);
    }

    FreeMemory(request.Images);
  }

  // Send kernel read request
  if (wcscmp(argv[1], L"/ReadKernel") == 0)
  {
    KDRV_READ_KERNEL_REQUEST request;
    request.ImageName = ArgvToMbStr(argv[2]);
    request.ExportName = ArgvToMbStr(argv[3]);
    request.Size = wcstoul(argv[5], NULL, 10);
    request.Offset = wcstoul(argv[4], NULL, 16);
    request.Buffer = AllocMemory<BYTE>(TRUE, request.Size);

    SIZE_T byteBlockSize = wcstoul(argv[6], NULL, 10);

    if (DeviceIoControl(device, KDRV_CTRL_READ_KERNEL_REQUEST, &request, sizeof(request), NULL, 0, NULL, NULL))
    {
      printf("0x%08X ", 0);
      for (SIZE_T i = 0; i < request.Size; i++)
      {
        printf("%02X ", request.Buffer[i]);
        if (i != 0 && (i + 1) < request.Size && (i + 1) % byteBlockSize == 0)
          printf("\n0x%08X ", (ULONG)i);
      }
      printf("\n\n");

      DisassembleBytes(request.Buffer, request.Size);
    }

    FreeMemory(request.ImageName);
    FreeMemory(request.ExportName);
    FreeMemory(request.Buffer);
  }

  // Send kernel write request
  if (wcscmp(argv[1], L"/WriteKernel") == 0)
  {
    KDRV_WRITE_KERNEL_REQUEST request;
    request.ImageName = ArgvToMbStr(argv[2]);
    request.ExportName = ArgvToMbStr(argv[3]);
    request.Buffer = ArgvToBytes(argv[6]);
    request.Offset = wcstoul(argv[4], NULL, 16);
    request.Size = wcstoul(argv[5], NULL, 10);

    DeviceIoControl(device, KDRV_CTRL_WRITE_KERNEL_REQUEST, &request, sizeof(request), NULL, 0, NULL, NULL);

    FreeMemory(request.ImageName);
    FreeMemory(request.ExportName);
    FreeMemory(request.Buffer);
  }

  // Send user read request
  if (wcscmp(argv[1], L"/ReadUser") == 0)
  {
    KDRV_READ_USER_REQUEST request;
    request.Pid = GetProcessId(argv[2]);
    request.ModuleName = ArgvToWcStr(argv[3]);
    request.Offset = wcstoul(argv[4], NULL, 16);
    request.Size = wcstoul(argv[5], NULL, 10);
    request.Buffer = AllocMemory<BYTE>(TRUE, request.Size);
    printf("pid: %u\n", request.Pid);
    SIZE_T byteBlockSize = wcstoul(argv[6], NULL, 10);

    if (DeviceIoControl(device, KDRV_CTRL_READ_USER_REQUEST, &request, sizeof(request), NULL, 0, NULL, NULL))
    {
      printf("0x%08X ", 0);
      for (SIZE_T i = 0; i < request.Size; i++)
      {
        printf("%02X ", request.Buffer[i]);
        if (i != 0 && (i + 1) < request.Size && (i + 1) % byteBlockSize == 0)
          printf("\n0x%08X ", (ULONG)i);
      }
      printf("\n\n");

      DisassembleBytes(request.Buffer, request.Size);
    }

    FreeMemory(request.Buffer);
  }

  // Send user write request
  if (wcscmp(argv[1], L"/WriteUser") == 0)
  {
    KDRV_WRITE_USER_REQUEST request;
    request.Pid = GetProcessId(argv[2]);
    request.ModuleName = ArgvToWcStr(argv[3]);
    request.Buffer = ArgvToBytes(argv[6]);
    request.Offset = wcstoul(argv[4], NULL, 16);
    request.Size = wcstoul(argv[5], NULL, 10);

    DeviceIoControl(device, KDRV_CTRL_WRITE_USER_REQUEST, &request, sizeof(request), NULL, 0, NULL, NULL);

    FreeMemory(request.Buffer);
  }

  // Debug request
  if (wcscmp(argv[1], L"/Debug") == 0)
  {
    if (DeviceIoControl(device, KDRV_CTRL_DEBUG_REQUEST, NULL, 0, NULL, 0, NULL, NULL))
    {
      
    }
  }

  CloseHandle(device);

  return 0;
}
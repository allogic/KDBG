#include "kcli.h"

SIZE_T ArgvLength(PCHAR argv)
{
  SIZE_T length = 0;
  while (*(argv++))
    ++length;
  return ++length;
}

INT main(INT argc, PPCHAR argv)
{
  ULONG written;
  HANDLE device = NULL;

  // Optain device handle
  device = CreateFileA("\\\\.\\KDRV", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
  if (device == INVALID_HANDLE_VALUE)
  {
    printf("KDRV is not running\n");
    return 0;
  }

  // Send kernel read request
  if (strcmp(argv[1], "/ReadKernel") == 0)
  {
    ULONG imageNameSize = (ULONG)ArgvLength(argv[2]);
    ULONG exportNameSize = (ULONG)ArgvLength(argv[3]);

    KDRV_READ_KERNEL_REQUEST request;
    request.ImageName = (PCHAR)malloc(imageNameSize);
    request.ExportName = (PCHAR)malloc(exportNameSize);
    request.Size = strtoul(argv[4], NULL, 10);

    memset(request.ImageName, 0, imageNameSize);
    memset(request.ExportName, 0, exportNameSize);
    memcpy(request.ImageName, argv[2], imageNameSize);
    memcpy(request.ExportName, argv[3], exportNameSize);

    ULONG byteBlockSize = strtoul(argv[5], NULL, 10);
    PBYTE bytes = (PBYTE)malloc(sizeof(BYTE) * request.Size);
    memset(bytes, 0, request.Size);

    if (DeviceIoControl(device, KDRV_CTRL_READ_KERNEL_REQUEST, &request, sizeof(request), bytes, sizeof(bytes), &written, NULL))
    {
      printf("Read kernel interrupt issued successfully\n");
      printf("0x%08X ", 0);
      for (ULONG i = 0; i < written; i++)
      {
        printf("%02X ", bytes[i]);
        if (i != 0 && (i + 1) < written && (i + 1) % byteBlockSize == 0)
          printf("\n0x%08X ", i);
      }
      printf("\n");
    }

    free(request.ImageName);
    free(request.ExportName);
    free(bytes);
  }

  // Send kernel write request
  if (strcmp(argv[1], "/WriteKernel") == 0)
  {
    ULONG imageNameSize = (ULONG)ArgvLength(argv[2]);
    ULONG exportNameSize = (ULONG)ArgvLength(argv[3]);

    KDRV_WRITE_KERNEL_REQUEST request;
    request.ImageName = (PCHAR)malloc(imageNameSize);
    request.ExportName = (PCHAR)malloc(exportNameSize);
    request.Size = strtoul(argv[4], NULL, 10);
    request.Bytes = (PBYTE)malloc(request.Size);

    memset(request.ImageName, 0, imageNameSize);
    memset(request.ExportName, 0, exportNameSize);
    memcpy(request.ImageName, argv[2], imageNameSize);
    memcpy(request.ExportName, argv[3], exportNameSize);
    memset(request.Bytes, 0x90, request.Size);

    if (DeviceIoControl(device, KDRV_CTRL_WRITE_KERNEL_REQUEST, &request, sizeof(request), NULL, 0, &written, NULL))
    {
      printf("Write kernel interrupt issued successfully\n");
    }

    free(request.ImageName);
    free(request.ExportName);
  }

  // Send user read request
  if (strcmp(argv[1], "/ReadUser") == 0)
  {
    // TODO implement me..
  }

  // Send user write request
  if (strcmp(argv[1], "/WriteUser") == 0)
  {
    // TODO implement me..
  }

  // Debug request
  if (strcmp(argv[1], "/Debug") == 0)
  {
    if (DeviceIoControl(device, KDRV_CTRL_DEBUG_REQUEST, NULL, 0, NULL, 0, &written, NULL))
    {
      printf("Debug interrupt issued successfully\n");
    }
  }

  CloseHandle(device);

  return 0;
}
#include "kcli.h"

ULONG ArgvLength(PWCHAR argv)
{
  ULONG length = 0;
  while (*(argv++))
    ++length;
  return ++length;
}
VOID ArgvToBytes(PBYTE bytes, PWCHAR argv, ULONG argvSize)
{
  WCHAR byte[2];
  for (ULONG i = 0, j = 0; i < (argvSize - 1); i += 2, j++)
  {
    memcpy(byte, argv + i, 2);
    bytes[j] = (BYTE)wcstoul(byte, NULL, 16);
  }
}

VOID DisassembleBytes(PBYTE bytes, SIZE_T size)
{
  csh csHandle;
  // Open capstone handle
  cs_err error = cs_open(CS_ARCH_X86, CS_MODE_64, &csHandle);
  if (error)
  {
    printf("cs_open\n");
    return;
  }
  // Optain instuctions
  cs_insn* instructions = NULL;
  SIZE_T numInstructions = cs_disasm(csHandle, bytes, size, 0, 0, &instructions);
  if (numInstructions)
  {
    // Print assembly instructions
    for (SIZE_T i = 0; i < numInstructions; ++i)
    {
      printf("0x%08X %s\t%s\n", (ULONG)instructions[i].address, instructions[i].mnemonic, instructions[i].op_str);
    }
  }
  // Cleanup
  cs_free(instructions, numInstructions);
  cs_close(&csHandle);
}

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
    request.Images = (PRTL_PROCESS_MODULES)malloc(sizeof(RTL_PROCESS_MODULES) * request.Size);

    if (DeviceIoControl(device, KDRV_CTRL_DUMP_KERNEL_IMAGE_REQUEST, &request, sizeof(request), NULL, 0, NULL, NULL))
    {
      for (ULONG i = 0; i < request.Images->NumberOfModules; ++i)
        printf("%p %s\n", request.Images->Modules[i].ImageBase, request.Images->Modules[i].FullPathName);
    }

    free(request.Images);
  }

  // Send dump user images
  if (wcscmp(argv[1], L"/DumpUserImages") == 0)
  {
    KDRV_DUMP_USER_IMAGE_REQUEST request;
    request.Size = 1024 * 1024;
    request.Images = (PSYSTEM_PROCESS_INFORMATION)malloc(sizeof(SYSTEM_PROCESS_INFORMATION) * request.Size);

    if (DeviceIoControl(device, KDRV_CTRL_DUMP_USER_IMAGE_REQUEST, &request, sizeof(request), NULL, 0, NULL, NULL))
    {
      for (ULONG i = 0; i < request.Size; ++i)
        if ((ULONG_PTR)request.Images[i].UniqueProcessId > 0 && (ULONG_PTR)request.Images[i].UniqueProcessId < ULONG_MAX)
          printf("%llu %ws\n", (ULONG_PTR)request.Images[i].UniqueProcessId, request.Images[i].ImageName.Buffer);
    }

    free(request.Images);
  }

  // Send kernel read request
  if (wcscmp(argv[1], L"/ReadKernel") == 0)
  {
    ULONG imageNameSizeBytes = sizeof(CHAR) * ArgvLength(argv[2]);
    ULONG exportNameSizeBytes = sizeof(CHAR) * ArgvLength(argv[3]);

    KDRV_READ_KERNEL_REQUEST request;
    request.ImageName = (PCHAR)malloc(imageNameSizeBytes);
    request.ExportName = (PCHAR)malloc(exportNameSizeBytes);
    request.Size = wcstoul(argv[5], NULL, 10);
    request.Offset = wcstoul(argv[4], NULL, 16);
    request.Buffer = (PBYTE)malloc(sizeof(BYTE) * request.Size);

    SIZE_T bytes = 0;
    wcstombs_s(&bytes, request.ImageName, imageNameSizeBytes, argv[2], 256);
    wcstombs_s(&bytes, request.ExportName, exportNameSizeBytes, argv[3], 256);
    memset(request.Buffer, 0, request.Size);

    ULONG byteBlockSize = wcstoul(argv[6], NULL, 10);

    if (DeviceIoControl(device, KDRV_CTRL_READ_KERNEL_REQUEST, &request, sizeof(request), NULL, 0, NULL, NULL))
    {
      printf("0x%08X ", 0);
      for (ULONG i = 0; i < request.Size; i++)
      {
        printf("%02X ", request.Buffer[i]);
        if (i != 0 && (i + 1) < request.Size && (i + 1) % byteBlockSize == 0)
          printf("\n0x%08X ", i);
      }
      printf("\n\n");

      DisassembleBytes(request.Buffer, request.Size);
    }

    free(request.ImageName);
    free(request.ExportName);
    free(request.Buffer);
  }

  // Send kernel write request
  if (wcscmp(argv[1], L"/WriteKernel") == 0)
  {
    ULONG imageNameSize = (ULONG)ArgvLength(argv[2]);
    ULONG exportNameSize = (ULONG)ArgvLength(argv[3]);
    ULONG bytePatchSize = (ULONG)ArgvLength(argv[6]);

    KDRV_WRITE_KERNEL_REQUEST request;
    request.ImageName = (PCHAR)malloc(imageNameSize);
    request.ExportName = (PCHAR)malloc(exportNameSize);
    request.Size = wcstoul(argv[5], NULL, 10);
    request.Offset = wcstoul(argv[4], NULL, 16);
    request.Bytes = (PBYTE)malloc(request.Size);

    memset(request.Bytes, 0x90, request.Size);
    memset(request.ImageName, 0, imageNameSize);
    memset(request.ExportName, 0, exportNameSize);

    memcpy(request.ImageName, argv[2], imageNameSize);
    memcpy(request.ExportName, argv[3], exportNameSize);

    ArgvToBytes(request.Bytes, argv[6], bytePatchSize);

    if (DeviceIoControl(device, KDRV_CTRL_WRITE_KERNEL_REQUEST, &request, sizeof(request), NULL, 0, NULL, NULL))
    {
      
    }

    free(request.ImageName);
    free(request.ExportName);
    free(request.Bytes);
  }

  // Send user read request
  if (wcscmp(argv[1], L"/ReadUser") == 0)
  {
    ULONG moduleNameSizeBytes = sizeof(WCHAR) * ArgvLength(argv[3]);

    KDRV_READ_USER_REQUEST request;
    request.Pid = wcstoul(argv[2], NULL, 10);
    request.ModuleName = (PWCHAR)malloc(moduleNameSizeBytes);
    request.Offset = (PVOID)wcstoull(argv[4], NULL, 16);
    request.Size = wcstoul(argv[5], NULL, 10);
    request.Buffer = (PBYTE)malloc(sizeof(BYTE) * request.Size);

    _wcsset_s(request.ModuleName, moduleNameSizeBytes, 0);
    memset(request.Buffer, 0, request.Size);

    wcscpy_s(request.ModuleName, moduleNameSizeBytes, argv[3]);

    ULONG byteBlockSize = wcstoul(argv[6], NULL, 10);

    printf("%ws\n", request.ModuleName);

    if (DeviceIoControl(device, KDRV_CTRL_READ_USER_REQUEST, &request, sizeof(request), NULL, 0, NULL, NULL))
    {
      printf("0x%08X ", 0);
      for (ULONG i = 0; i < request.Size; i++)
      {
        printf("%02X ", request.Buffer[i]);
        if (i != 0 && (i + 1) < request.Size && (i + 1) % byteBlockSize == 0)
          printf("\n0x%08X ", i);
      }
      printf("\n\n");

      DisassembleBytes(request.Buffer, request.Size);
    }

    free(request.Buffer);
  }

  // Send user write request
  if (wcscmp(argv[1], L"/WriteUser") == 0)
  {
    KDRV_WRITE_USER_REQUEST request;
    request.Pid = wcstoul(argv[2], NULL, 10);
    request.Size = wcstoul(argv[4], NULL, 10);
    request.Offset = (PVOID)wcstoull(argv[3], NULL, 16);
    request.Buffer = (PBYTE)malloc(sizeof(BYTE) * request.Size);

    memset(request.Buffer, 0, request.Size);

    if (DeviceIoControl(device, KDRV_CTRL_READ_USER_REQUEST, &request, sizeof(request), NULL, 0, NULL, NULL))
    {
      
    }

    free(request.Buffer);
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
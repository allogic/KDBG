#include "kcli.h"

ULONG ArgvLength(PCHAR argv)
{
  ULONG length = 0;
  while (*(argv++))
    ++length;
  return ++length;
}
VOID ArgvToBytes(PBYTE bytes, PCHAR argv, ULONG argvSize)
{
  CHAR byte[2];
  for (ULONG i = 0, j = 0; i < (argvSize - 1); i += 2, j++)
  {
    memcpy(byte, argv + i, 2);
    bytes[j] = (BYTE)strtoul(byte, NULL, 16);
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

INT main(INT argc, PPCHAR argv)
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
  if (strcmp(argv[1], "/DumpKernelImages") == 0)
  {
    KDRV_DUMP_KERNEL_IMAGE_REQUEST request;
    request.Size = 1024 * 1024;
    request.Images = (PRTL_PROCESS_MODULES)malloc(sizeof(RTL_PROCESS_MODULES) * request.Size);

    if (DeviceIoControl(device, KDRV_CTRL_DUMP_KERNEL_IMAGE_REQUEST, &request, sizeof(request), NULL, 0, NULL, NULL))
    {
      for (SIZE_T i = 0; i < request.Images->NumberOfModules; ++i)
        printf("%p %s\n", request.Images->Modules[i].ImageBase, request.Images->Modules[i].FullPathName);
    }

    free(request.Images);
  }

  // Send dump user images
  if (strcmp(argv[1], "/DumpUserImages") == 0)
  {
    KDRV_DUMP_USER_IMAGE_REQUEST request;
    request.Pid = strtoul(argv[2], NULL, 10);
    request.Size = 1024 * 1024;
    request.Images = malloc(request.Size);

    if (DeviceIoControl(device, KDRV_CTRL_DUMP_USER_IMAGE_REQUEST, NULL, 0, NULL, 0, NULL, NULL))
    {
      
    }

    free(request.Images);
  }

  // Send kernel read request
  if (strcmp(argv[1], "/ReadKernel") == 0)
  {
    ULONG imageNameSize = (ULONG)ArgvLength(argv[2]);
    ULONG exportNameSize = (ULONG)ArgvLength(argv[3]);

    KDRV_READ_KERNEL_REQUEST request;
    request.ImageName = (PCHAR)malloc(imageNameSize);
    request.ExportName = (PCHAR)malloc(exportNameSize);
    request.Size = strtoul(argv[5], NULL, 10);
    request.Buffer = (PBYTE)malloc(sizeof(BYTE) * request.Size);
    request.Offset = strtoul(argv[4], NULL, 16);

    memset(request.ImageName, 0, imageNameSize);
    memset(request.ExportName, 0, exportNameSize);
    memset(request.Buffer, 0, request.Size);

    memcpy(request.ImageName, argv[2], imageNameSize);
    memcpy(request.ExportName, argv[3], exportNameSize);

    ULONG byteBlockSize = strtoul(argv[6], NULL, 10);

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
  if (strcmp(argv[1], "/WriteKernel") == 0)
  {
    ULONG imageNameSize = (ULONG)ArgvLength(argv[2]);
    ULONG exportNameSize = (ULONG)ArgvLength(argv[3]);
    ULONG bytePatchSize = (ULONG)ArgvLength(argv[6]);

    KDRV_WRITE_KERNEL_REQUEST request;
    request.ImageName = (PCHAR)malloc(imageNameSize);
    request.ExportName = (PCHAR)malloc(exportNameSize);
    request.Size = strtoul(argv[5], NULL, 10);
    request.Bytes = (PBYTE)malloc(request.Size);
    request.Offset = strtoul(argv[4], NULL, 16);

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
  if (strcmp(argv[1], "/ReadUser") == 0)
  {
    KDRV_READ_USER_REQUEST request;
    request.Pid = strtoul(argv[2], NULL, 10);
    request.Size = strtoul(argv[4], NULL, 10);
    request.Buffer = (PBYTE)malloc(sizeof(BYTE) * request.Size);
    request.Offset = (PVOID)strtoull(argv[3], NULL, 16);

    memset(request.Buffer, 0, request.Size);

    ULONG byteBlockSize = strtoul(argv[6], NULL, 10);

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
  if (strcmp(argv[1], "/WriteUser") == 0)
  {
    KDRV_WRITE_USER_REQUEST request;
    request.Pid = strtoul(argv[2], NULL, 10);
    request.Size = strtoul(argv[4], NULL, 10);
    request.Buffer = (PBYTE)malloc(sizeof(BYTE) * request.Size);
    request.Offset = (PVOID)strtoull(argv[3], NULL, 16);

    memset(request.Buffer, 0, request.Size);

    if (DeviceIoControl(device, KDRV_CTRL_READ_USER_REQUEST, &request, sizeof(request), NULL, 0, NULL, NULL))
    {
      
    }

    free(request.Buffer);
  }

  // Debug request
  if (strcmp(argv[1], "/Debug") == 0)
  {
    if (DeviceIoControl(device, KDRV_CTRL_DEBUG_REQUEST, NULL, 0, NULL, 0, NULL, NULL))
    {
      
    }
  }

  CloseHandle(device);

  return 0;
}
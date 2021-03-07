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
  for (ULONG i = 0, j = 0; i < argvSize; i += 2, j++)
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
      printf("0x%llX:\t%s\t%s\n", instructions[i].address, instructions[i].mnemonic, instructions[i].op_str);
    }
  }
  // Cleanup
  cs_free(instructions, numInstructions);
  cs_close(&csHandle);
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

  // Send dump kernel images
  if (strcmp(argv[1], "/DumpKernelImages") == 0)
  {
    KDRV_DUMP_KERNEL_IMAGE_REQUEST request;
    request.Images = (PRTL_PROCESS_MODULES)malloc(sizeof(RTL_PROCESS_MODULES) * 1024 * 1024);

    // TODO finish these dump requests first..

    if (DeviceIoControl(device, KDRV_CTRL_DUMP_KERNEL_IMAGE_REQUEST, &request, sizeof(request), NULL, 0, &written, NULL))
    {
      for (SIZE_T i = 0; i < request.Images->NumberOfModules; ++i)
        printf("%p %s\n", request.Images->Modules[i].ImageBase, request.Images->Modules[i].FullPathName);
    }

    free(request.Images);
  }

  // Send dump user images
  if (strcmp(argv[1], "/DumpUserImages") == 0)
  {
    if (DeviceIoControl(device, KDRV_CTRL_DUMP_USER_IMAGE_REQUEST, NULL, 0, NULL, 0, &written, NULL))
    {
      // TODO implement me..
    }
  }

  // Send kernel read request
  if (strcmp(argv[1], "/ReadKernel") == 0)
  {
    ULONG imageNameSize = (ULONG)ArgvLength(argv[2]);
    ULONG exportNameSize = (ULONG)ArgvLength(argv[3]);

    KDRV_READ_KERNEL_REQUEST request;
    request.ImageName = (PCHAR)malloc(imageNameSize);
    request.ExportName = (PCHAR)malloc(exportNameSize);
    request.Offset = strtoul(argv[4], NULL, 16);
    request.Size = strtoul(argv[5], NULL, 10);

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
      DisassembleBytes(bytes, request.Size);
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
    ULONG bytePatchSize = (ULONG)ArgvLength(argv[6]);

    KDRV_WRITE_KERNEL_REQUEST request;
    request.ImageName = (PCHAR)malloc(imageNameSize);
    request.ExportName = (PCHAR)malloc(exportNameSize);
    request.Offset = strtoul(argv[4], NULL, 16);
    request.Size = strtoul(argv[5], NULL, 10);
    
    request.Bytes = (PBYTE)malloc(request.Size);

    memset(request.Bytes, 0x90, request.Size);
    ArgvToBytes(request.Bytes, argv[6], bytePatchSize);

    memset(request.ImageName, 0, imageNameSize);
    memset(request.ExportName, 0, exportNameSize);
    memcpy(request.ImageName, argv[2], imageNameSize);
    memcpy(request.ExportName, argv[3], exportNameSize);

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
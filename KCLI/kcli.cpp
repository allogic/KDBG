#include "kcli.h"
#include "util.h"

HANDLE Device = INVALID_HANDLE_VALUE;

INT wmain(INT argc, PWCHAR argv[])
{
  // Optain communication device
  Device = CreateFileA("\\\\.\\KDRV", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
  if (Device == INVALID_HANDLE_VALUE)
  {
    printf("KDRV link failed\n");
    return 1;
  }
  // Dump kernel modules
  if (wcscmp(argv[1], L"/DumpKernelModules") == 0)
  {
    ULONG bufferSize = wcstoul(argv[2], NULL, 10);
    KDRV_REQ_DUMP_MODULES request;
    request.Mode = KDRV_REQ_DUMP_MODULES::Kernel;
    request.Buffer = malloc(sizeof(RTL_PROCESS_MODULES) * bufferSize);
    if (DeviceIoControl(Device, KDRV_CTRL_DUMP_MODULES, &request, sizeof(request), &request, sizeof(request), NULL, NULL))
    {
      printf("Size: %u\n", request.Size);
      printf("Buffer: %p\n", request.Buffer);
      PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)request.Buffer;
      PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
      for (ULONG i = 0; i < modules->NumberOfModules; ++i)
      {
        printf("Base: %p\n", module[i].ImageBase);
        printf("Name: %s\n", (PCHAR)(module[i].FullPathName + module[i].OffsetToFileName));
        printf("Size: %u\n", module[i].ImageSize);
      }
    }
    free(request.Buffer);
  }
  // Dump user modules
  if (wcscmp(argv[1], L"/DumpUserModules") == 0)
  {
    KDRV_REQ_DUMP_MODULES request;
    request.Mode = KDRV_REQ_DUMP_MODULES::User;
    request.Pid = wcstoul(argv[2], NULL, 10);
    request.Size = wcstoul(argv[3], NULL, 10);
    request.Buffer = malloc(sizeof(LDR_DATA_TABLE_ENTRY) * request.Size);
    if (DeviceIoControl(Device, KDRV_CTRL_DUMP_MODULES, &request, sizeof(request), &request, sizeof(request), NULL, NULL))
    {
      printf("Size: %u\n", request.Size);
      printf("Buffer: %p\n", request.Buffer);
      PLDR_DATA_TABLE_ENTRY ldrs = (PLDR_DATA_TABLE_ENTRY)request.Buffer;
      for (ULONG i = 0; i < request.Size; ++i)
      {
        printf("Base: %p\n", ldrs[i].DllBase);
        printf("Name: %wZ\n", &ldrs[i].FullDllName);
        printf("Size: %u\n", ldrs[i].SizeOfImage);
      }
    }
    free(request.Buffer);
  }
  // Dump process threads
  if (wcscmp(argv[1], L"/DumpUserThreads") == 0)
  {
    KDRV_REQ_DUMP_THREADS request;
    request.Pid = wcstoul(argv[2], NULL, 10);
    request.Tid = wcstoul(argv[3], NULL, 10);
    request.Size = wcstoul(argv[4], NULL, 10);
    request.Buffer = malloc(sizeof(SYSTEM_THREAD_INFORMATION) * request.Size);
    if (DeviceIoControl(Device, KDRV_CTRL_DUMP_THREADS, &request, sizeof(request), &request, sizeof(request), NULL, NULL))
    {
      PSYSTEM_THREAD_INFORMATION threads = (PSYSTEM_THREAD_INFORMATION)request.Buffer;
      for (ULONG i = 0; i < request.Size; ++i)
        printf("Pid: %u Tid: %u BaseAddress: %p\n", *(PULONG)threads[i].ClientId.UniqueProcess, *(PULONG)threads[i].ClientId.UniqueThread, threads[i].StartAddress);
      printf("\n");
    }
    free(request.Buffer);
  }
  // Dump thread registers
  if (wcscmp(argv[1], L"/DumpRegisters") == 0)
  {
    KDRV_REQ_DUMP_REGISTERS request;
    request.Pid = GetProcessId(argv[2]);
    request.Tid = wcstoul(argv[3], NULL, 10);
    if (DeviceIoControl(Device, KDRV_CTRL_DUMP_REGISTERS, &request, sizeof(request), &request, sizeof(KDRV_REQ_DUMP_REGISTERS), NULL, NULL))
    {
      printf("EAX: %u\n", request.Registers.Eax);
      printf("EBX: %u\n", request.Registers.Ebx);
      printf("ECX: %u\n", request.Registers.Ecx);
      printf("EDX: %u\n", request.Registers.Edx);
      printf("\n");
      printf("EBP: %u\n", request.Registers.Ebp);
      printf("EIP: %u\n", request.Registers.Eip);
      printf("ESP: %u\n", request.Registers.Esp);
      printf("\n");
      printf("EDI: %u\n", request.Registers.Edi);
      printf("ESI: %u\n", request.Registers.Esi);
      printf("\n");
      printf("DR0: %u\n", request.Registers.Dr0);
      printf("DR1: %u\n", request.Registers.Dr1);
      printf("DR2: %u\n", request.Registers.Dr2);
      printf("DR3: %u\n", request.Registers.Dr3);
      printf("DR6: %u\n", request.Registers.Dr6);
      printf("DR7: %u\n", request.Registers.Dr7);
      printf("\n");
    }
  }
  // Close communication device
  if (!CloseHandle(Device))
  {
    printf("KDRV link failed\n");
    return 1;
  }
  return 0;
}
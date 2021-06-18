#include "kcli.h"
#include "util.h"

HANDLE Device = INVALID_HANDLE_VALUE;

INT wmain(INT argc, PWCHAR argv[])
{
  // Optain communication device
  Device = CreateFileA("\\\\.\\KDRV", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
  if (Device == INVALID_HANDLE_VALUE)
  {
    std::printf("KDRV link failed\n");
    return 1;
  }
  // Dump processes
  if (std::wcscmp(argv[1], L"/DumpImages") == 0)
  {
    KDRV_REQ_DUMP_IMAGES request;
    request.Size = std::wcstoul(argv[2], NULL, 10);
    request.Images = (PSYSTEM_PROCESS_INFORMATION)std::malloc(sizeof(SYSTEM_PROCESS_INFORMATION) * request.Size);
    if (DeviceIoControl(Device, KDRV_CTRL_DUMP_MODULES, &request, sizeof(request), NULL, 0, NULL, NULL))
    {
      for (ULONG i = 0; i < request.Size; ++i)
        std::printf("Pid: %u Name: %wZ\n", *(PULONG)request.Images[i].UniqueProcessId, &request.Images[i].ImageName);
      std::printf("\n");
    }
    std::free(request.Images);
  }
  // Dump process modules
  if (std::wcscmp(argv[1], L"/DumpModules") == 0)
  {
    KDRV_REQ_DUMP_MODULES request;
    request.Pid = GetProcessId(argv[2]);
    request.Size = std::wcstoul(argv[3], NULL, 10);
    request.Modules = (PRTL_PROCESS_MODULES)std::malloc(sizeof(RTL_PROCESS_MODULES) * request.Size);
    if (DeviceIoControl(Device, KDRV_CTRL_DUMP_MODULES, &request, sizeof(request), NULL, 0, NULL, NULL))
    {
      for (ULONG i = 0; i < request.Size; ++i)
        std::printf("Name: %s BaseAddress: %p\n", (PCHAR)request.Modules[i].Modules[0].FullPathName, request.Modules[i].Modules[0].ImageBase);
      std::printf("\n");
    }
    std::free(request.Modules);
  }
  // Dump process threads
  if (std::wcscmp(argv[1], L"/DumpThreads") == 0)
  {
    KDRV_REQ_DUMP_THREADS request;
    request.Pid = GetProcessId(argv[2]);
    request.Size = std::wcstoul(argv[3], NULL, 10);
    request.Threads = (PSYSTEM_THREAD_INFORMATION)std::malloc(sizeof(SYSTEM_THREAD_INFORMATION) * request.Size);
    if (DeviceIoControl(Device, KDRV_CTRL_DUMP_THREADS, &request, sizeof(request), NULL, 0, NULL, NULL))
    {
      for (ULONG i = 0; i < request.Size; ++i)
        std::printf("Pid: %u Tid: %u BaseAddress: %p\n", *(PULONG)request.Threads[i].ClientId.UniqueProcess, *(PULONG)request.Threads[i].ClientId.UniqueThread, request.Threads[i].StartAddress);
      std::printf("\n");
    }
    std::free(request.Threads);
  }
  // Dump thread registers
  if (std::wcscmp(argv[1], L"/DumpRegisters") == 0)
  {
    KDRV_REQ_DUMP_REGISTERS request;
    request.Pid = GetProcessId(argv[2]);
    request.Tid = std::wcstoul(argv[3], NULL, 10);
    if (DeviceIoControl(Device, KDRV_CTRL_DUMP_REGISTERS, &request, sizeof(request), NULL, 0, NULL, NULL))
    {
      std::printf("EAX: %u\n", request.Registers.Eax);
      std::printf("EBX: %u\n", request.Registers.Ebx);
      std::printf("ECX: %u\n", request.Registers.Ecx);
      std::printf("EDX: %u\n", request.Registers.Edx);
      std::printf("\n");
      std::printf("EBP: %u\n", request.Registers.Ebp);
      std::printf("EIP: %u\n", request.Registers.Eip);
      std::printf("ESP: %u\n", request.Registers.Esp);
      std::printf("\n");
      std::printf("EDI: %u\n", request.Registers.Edi);
      std::printf("ESI: %u\n", request.Registers.Esi);
      std::printf("\n");
      std::printf("DR0: %u\n", request.Registers.Dr0);
      std::printf("DR1: %u\n", request.Registers.Dr1);
      std::printf("DR2: %u\n", request.Registers.Dr2);
      std::printf("DR3: %u\n", request.Registers.Dr3);
      std::printf("DR6: %u\n", request.Registers.Dr6);
      std::printf("DR7: %u\n", request.Registers.Dr7);
      std::printf("\n");
    }
  }
  // Close communication device
  if (!CloseHandle(Device))
  {
    std::printf("KDRV link failed\n");
    return 1;
  }
  return 0;
}
#include "kcli.h"
#include "util.h"

HANDLE Device = INVALID_HANDLE_VALUE;

INT wmain(INT argc, PWCHAR argv[])
{
  // Optain communication device
  Device = CreateFileA("\\\\.\\KDRV", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
  if (Device == INVALID_HANDLE_VALUE)
  {
    LOG_INFO("KDRV link failed\n");
    return 1;
  }
  // Dump kernel modules
  if (wcscmp(argv[1], L"/DumpKernelModules") == 0)
  {
    KDRV_REQ_DUMP_MODULES request;
    request.Mode = KDRV_REQ_DUMP_MODULES::Kernel;
    request.Size = wcstoul(argv[2], NULL, 10);
    request.Buffer = malloc(sizeof(RTL_PROCESS_MODULES) * request.Size);
    if (DeviceIoControl(Device, KDRV_CTRL_DUMP_MODULES, &request, sizeof(request), &request, sizeof(request), NULL, NULL))
    {
      LOG_INFO("Size: %u\n", request.Size);
      LOG_INFO("Buffer: %p\n", request.Buffer);
      PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)request.Buffer;
      PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
      for (ULONG i = 0; i < modules->NumberOfModules; ++i)
      {
        LOG_INFO("Base: %p\n", module[i].ImageBase);
        LOG_INFO("Name: %s\n", (PCHAR)(module[i].FullPathName + module[i].OffsetToFileName));
        LOG_INFO("Size: %u\n", module[i].ImageSize);
      }
    }
    free(request.Buffer);
  }
  // Dump user modules
  if (wcscmp(argv[1], L"/DumpUserModules") == 0)
  {
    KDRV_REQ_DUMP_MODULES request;
    request.Mode = KDRV_REQ_DUMP_MODULES::User;
    request.Pid = GetProcId(L"TaskMgr.exe");
    request.Size = wcstoul(argv[3], NULL, 10);
    request.Buffer = malloc(sizeof(LDR_DATA_TABLE_ENTRY) * request.Size);
    if (DeviceIoControl(Device, KDRV_CTRL_DUMP_MODULES, &request, sizeof(request), &request, sizeof(request), NULL, NULL))
    {
      LOG_INFO("Size: %u\n", request.Size);
      LOG_INFO("Buffer: %p\n", request.Buffer);
      PLDR_DATA_TABLE_ENTRY ldrs = (PLDR_DATA_TABLE_ENTRY)request.Buffer;
      for (ULONG i = 0; i < request.Size; ++i)
      {
        LOG_INFO("Base: %p\n", ldrs[i].DllBase);
        LOG_INFO("Name: %wZ\n", &ldrs[i].FullDllName);
        LOG_INFO("Size: %u\n", ldrs[i].SizeOfImage);
      }
    }
    free(request.Buffer);
  }
  // Dump process threads
  if (wcscmp(argv[1], L"/DumpUserThreads") == 0)
  {
    KDRV_REQ_DUMP_THREADS request;
    request.Pid = GetProcId(L"TaskMgr.exe");
    request.Tid = wcstoul(argv[3], NULL, 10);
    request.Size = wcstoul(argv[4], NULL, 10);
    request.Buffer = malloc(sizeof(SYSTEM_THREAD_INFORMATION) * request.Size);
    if (DeviceIoControl(Device, KDRV_CTRL_DUMP_THREADS, &request, sizeof(request), &request, sizeof(request), NULL, NULL))
    {
      PSYSTEM_THREAD_INFORMATION threads = (PSYSTEM_THREAD_INFORMATION)request.Buffer;
      for (ULONG i = 0; i < request.Size; ++i)
        LOG_INFO("Pid: %u Tid: %u BaseAddress: %p\n", *(PULONG)threads[i].ClientId.UniqueProcess, *(PULONG)threads[i].ClientId.UniqueThread, threads[i].StartAddress);
      LOG_INFO("\n");
    }
    free(request.Buffer);
  }
  // Dump thread registers
  if (wcscmp(argv[1], L"/DumpUserThreadRegisters") == 0)
  {
    KDRV_REQ_DUMP_REGISTERS request;
    request.Pid = GetProcId(L"TaskMgr.exe");
    request.Tid = wcstoul(argv[3], NULL, 10);
    if (DeviceIoControl(Device, KDRV_CTRL_DUMP_REGISTERS, &request, sizeof(request), &request, sizeof(request), NULL, NULL))
    {
      LOG_INFO("EAX: %u\n", request.Registers.Eax);
      LOG_INFO("EBX: %u\n", request.Registers.Ebx);
      LOG_INFO("ECX: %u\n", request.Registers.Ecx);
      LOG_INFO("EDX: %u\n", request.Registers.Edx);
      LOG_INFO("\n");
      LOG_INFO("EBP: %u\n", request.Registers.Ebp);
      LOG_INFO("EIP: %u\n", request.Registers.Eip);
      LOG_INFO("ESP: %u\n", request.Registers.Esp);
      LOG_INFO("\n");
      LOG_INFO("EDI: %u\n", request.Registers.Edi);
      LOG_INFO("ESI: %u\n", request.Registers.Esi);
      LOG_INFO("\n");
      LOG_INFO("DR0: %u\n", request.Registers.Dr0);
      LOG_INFO("DR1: %u\n", request.Registers.Dr1);
      LOG_INFO("DR2: %u\n", request.Registers.Dr2);
      LOG_INFO("DR3: %u\n", request.Registers.Dr3);
      LOG_INFO("DR6: %u\n", request.Registers.Dr6);
      LOG_INFO("DR7: %u\n", request.Registers.Dr7);
      LOG_INFO("\n");
    }
  }
  // Suspend user thread
  if (wcscmp(argv[1], L"/SuspendUserThread") == 0)
  {
    KDRV_REQ_THREAD_SUSPEND request;
    request.Pid = GetProcId(L"TaskMgr.exe");
    request.Tid = 666;
    if (DeviceIoControl(Device, KDRV_CTRL_THREAD_SUSPEND, &request, sizeof(request), &request, sizeof(request), NULL, NULL))
    {
      LOG_INFO("Thread suspended\n");
    }
  }
  // Resume user thread
  if (wcscmp(argv[1], L"/ResumeUserThread") == 0)
  {
    KDRV_REQ_THREAD_RESUME request;
    request.Pid = GetProcId(L"TaskMgr.exe");
    request.Tid = 666;
    if (DeviceIoControl(Device, KDRV_CTRL_THREAD_RESUME, &request, sizeof(request), &request, sizeof(request), NULL, NULL))
    {
      LOG_INFO("Thread resumed\n");
    }
  }
  // Close communication device
  if (!CloseHandle(Device))
  {
    LOG_INFO("KDRV link failed\n");
    return 1;
  }
  return 0;
}
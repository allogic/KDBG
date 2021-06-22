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
    request.Modules = (KDRV_REQ_DUMP_MODULES::PMODULE)malloc(sizeof(KDRV_REQ_DUMP_MODULES::PMODULE) * request.Size);
    if (DeviceIoControl(Device, KDRV_CTRL_DUMP_MODULES, &request, sizeof(request), &request, sizeof(request), NULL, NULL))
    {
      for (ULONG i = 0; i < request.Size; ++i)
      {
        LOG_INFO("Base: %p\n", ((KDRV_REQ_DUMP_MODULES::PMODULE)request.Modules)[i].Base);
        LOG_INFO("Name: %s\n", ((KDRV_REQ_DUMP_MODULES::PMODULE)request.Modules)[i].Name);
        LOG_INFO("Size: %u\n", ((KDRV_REQ_DUMP_MODULES::PMODULE)request.Modules)[i].Size);
      }
    }
    free(request.Modules);
  }
  // Dump user modules
  if (wcscmp(argv[1], L"/DumpUserModules") == 0)
  {
    KDRV_REQ_DUMP_MODULES request;
    request.Mode = KDRV_REQ_DUMP_MODULES::User;
    request.Pid = wcstoul(argv[2], NULL, 10);
    request.Size = wcstoul(argv[3], NULL, 10);
    request.Modules = (KDRV_REQ_DUMP_MODULES::PMODULE)malloc(sizeof(KDRV_REQ_DUMP_MODULES::PMODULE) * request.Size);
    if (DeviceIoControl(Device, KDRV_CTRL_DUMP_MODULES, &request, sizeof(request), &request, sizeof(request), NULL, NULL))
    {
      for (ULONG i = 0; i < request.Size; ++i)
      {
        LOG_INFO("Base: %p\n", ((KDRV_REQ_DUMP_MODULES::PMODULE)request.Modules)[i].Base);
        LOG_INFO("Name: %s\n", ((KDRV_REQ_DUMP_MODULES::PMODULE)request.Modules)[i].Name);
        LOG_INFO("Size: %u\n", ((KDRV_REQ_DUMP_MODULES::PMODULE)request.Modules)[i].Size);
      }
    }
    free(request.Modules);
  }
  // Dump process threads
  if (wcscmp(argv[1], L"/DumpUserThreads") == 0)
  {
    KDRV_REQ_DUMP_THREADS request;
    request.Size = wcstoul(argv[2], NULL, 10);
    request.Threads = (KDRV_REQ_DUMP_THREADS::PTHREAD)malloc(sizeof(KDRV_REQ_DUMP_THREADS::PTHREAD) * request.Size);
    if (DeviceIoControl(Device, KDRV_CTRL_DUMP_THREADS, &request, sizeof(request), &request, sizeof(request), NULL, NULL))
    {
      for (ULONG i = 0; i < request.Size; ++i)
      {
        LOG_INFO("Pid: %u\n", ((KDRV_REQ_DUMP_THREADS::PTHREAD)request.Threads)[i].Pid);
        LOG_INFO("Tid: %u\n", ((KDRV_REQ_DUMP_THREADS::PTHREAD)request.Threads)[i].Tid);
        LOG_INFO("Start: %p\n", ((KDRV_REQ_DUMP_THREADS::PTHREAD)request.Threads)[i].Start);
        LOG_INFO("State: %u\n", ((KDRV_REQ_DUMP_THREADS::PTHREAD)request.Threads)[i].State);
      }
    }
    free(request.Threads);
  }
  // Dump thread registers
  if (wcscmp(argv[1], L"/DumpUserThreadRegisters") == 0)
  {
    KDRV_REQ_DUMP_REGISTERS request;
    request.Tid = wcstoul(argv[2], NULL, 10);
    if (DeviceIoControl(Device, KDRV_CTRL_DUMP_REGISTERS, &request, sizeof(request), &request, sizeof(request), NULL, NULL))
    {
      LOG_INFO("Control flags\n");
      LOG_INFO("ContextFlags: %u\n", request.Registers.ContextFlags);
      LOG_INFO("MxCsr: %u\n", request.Registers.MxCsr);
      LOG_INFO("\n");
      LOG_INFO("Segment registers and processor flags\n");
      LOG_INFO("SegCs: %u\n", request.Registers.SegCs);
      LOG_INFO("SegDs: %u\n", request.Registers.SegDs);
      LOG_INFO("SegEs: %u\n", request.Registers.SegEs);
      LOG_INFO("SegFs: %u\n", request.Registers.SegFs);
      LOG_INFO("SegGs: %u\n", request.Registers.SegGs);
      LOG_INFO("SegSs: %u\n", request.Registers.SegSs);
      LOG_INFO("EFlags: %u\n", request.Registers.EFlags);
      LOG_INFO("\n");
      LOG_INFO("Debug registers\n");
      LOG_INFO("Dr0: %llu\n", request.Registers.Dr0);
      LOG_INFO("Dr1: %llu\n", request.Registers.Dr1);
      LOG_INFO("Dr2: %llu\n", request.Registers.Dr2);
      LOG_INFO("Dr3: %llu\n", request.Registers.Dr3);
      LOG_INFO("Dr6: %llu\n", request.Registers.Dr6);
      LOG_INFO("Dr7: %llu\n", request.Registers.Dr7);
      LOG_INFO("\n");
      LOG_INFO("Integer registers\n");
      LOG_INFO("Rax: %llu\n", request.Registers.Rax);
      LOG_INFO("Rcx: %llu\n", request.Registers.Rcx);
      LOG_INFO("Rdx: %llu\n", request.Registers.Rdx);
      LOG_INFO("Rbx: %llu\n", request.Registers.Rbx);
      LOG_INFO("Rsp: %llu\n", request.Registers.Rsp);
      LOG_INFO("Rbp: %llu\n", request.Registers.Rbp);
      LOG_INFO("Rsi: %llu\n", request.Registers.Rsi);
      LOG_INFO("Rdi: %llu\n", request.Registers.Rdi);
      LOG_INFO("R8: %llu\n", request.Registers.R8);
      LOG_INFO("R9: %llu\n", request.Registers.R9);
      LOG_INFO("R10: %llu\n", request.Registers.R10);
      LOG_INFO("R11: %llu\n", request.Registers.R11);
      LOG_INFO("R12: %llu\n", request.Registers.R12);
      LOG_INFO("R13: %llu\n", request.Registers.R13);
      LOG_INFO("R14: %llu\n", request.Registers.R14);
      LOG_INFO("R15: %llu\n", request.Registers.R15);
      LOG_INFO("\n");
      LOG_INFO("Program counter\n");
      LOG_INFO("Rip: %llu\n", request.Registers.Rip);
      LOG_INFO("\n");
      LOG_INFO("Special debug control registers\n");
      LOG_INFO("DebugControl: %llu\n", request.Registers.DebugControl);
      LOG_INFO("LastBranchToRip: %llu\n", request.Registers.LastBranchToRip);
      LOG_INFO("LastBranchFromRip: %llu\n", request.Registers.LastBranchFromRip);
      LOG_INFO("LastExceptionToRip: %llu\n", request.Registers.LastExceptionToRip);
      LOG_INFO("LastExceptionFromRip: %llu\n", request.Registers.LastExceptionFromRip);
    }
  }
  // Suspend user thread
  if (wcscmp(argv[1], L"/SuspendUserThread") == 0)
  {
    KDRV_REQ_THREAD_SUSPEND request;
    request.Pid = wcstoul(argv[2], NULL, 10);
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
    request.Pid = wcstoul(argv[2], NULL, 10);
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
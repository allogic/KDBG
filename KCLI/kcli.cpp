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
  if (wcscmp(argv[1], L"/DumpKernelImages") == 0)
  {
    KDRV_REQ_DUMP_KRNL_IMAGES request;
    request.ModuleCount = wcstoul(argv[2], NULL, 10);
    request.Modules = (KDRV_REQ_DUMP_KRNL_IMAGES::PMODULE)malloc(sizeof(KDRV_REQ_DUMP_KRNL_IMAGES::MODULE) * request.ModuleCount);
    if (DeviceIoControl(Device, KDRV_CTRL_DUMP_KRNL_IMAGES, &request, sizeof(request), &request, sizeof(request), NULL, NULL))
    {
      for (ULONG i = 0; i < request.ModuleCount; ++i)
      {
        LOG_INFO("Name: %s\n", request.Modules[i].Name);
        LOG_INFO("Base: %p\n", request.Modules[i].Base);
        LOG_INFO("Size: %u\n", request.Modules[i].Size);
        LOG_INFO("\n");
      }
    }
    free(request.Modules);
  }
  // Dump user modules
  if (wcscmp(argv[1], L"/DumpUserProcesses") == 0)
  {
    KDRV_REQ_DUMP_PROCESSES request;
    request.ProcessCount = wcstoul(argv[2], NULL, 10);
    request.ThreadCount = wcstoul(argv[3], NULL, 10);
    request.Processes = (KDRV_REQ_DUMP_PROCESSES::PPROCESS)malloc(sizeof(KDRV_REQ_DUMP_PROCESSES::PROCESS) * request.ProcessCount);
    memset(request.Processes, 0, sizeof(KDRV_REQ_DUMP_PROCESSES::PROCESS) * request.ProcessCount);
    for (ULONG i = 0; i < request.ProcessCount; ++i)
    {
      request.Processes[i].Threads = (KDRV_REQ_DUMP_PROCESSES::PTHREAD)malloc(sizeof(KDRV_REQ_DUMP_PROCESSES::THREAD) * request.ThreadCount);
      memset(request.Processes[i].Threads, 0, sizeof(KDRV_REQ_DUMP_PROCESSES::THREAD) * request.ThreadCount);
    }
    if (DeviceIoControl(Device, KDRV_CTRL_DUMP_PROCESSES, &request, sizeof(request), &request, sizeof(request), NULL, NULL))
    {
      for (ULONG i = 0; i < request.ProcessCount; ++i)
      {
        LOG_INFO("Pid: %u\n", request.Processes[i].Pid);
        LOG_INFO("Name: %wZ\n", request.Processes[i].Name);
        LOG_INFO("Threads:\n");
        for (ULONG j = 0; j < request.ThreadCount; ++j)
        {
          LOG_INFO("\tTid: %u\n", request.Processes[i].Threads[j].Tid);
          LOG_INFO("\tBase: %p\n", request.Processes[i].Threads[j].Base);
          LOG_INFO("\tState: %u\n", request.Processes[i].Threads[j].State);
        }
      }
    }
    for (ULONG i = 0; i < request.ProcessCount; ++i)
    {
      free(request.Processes[i].Threads);
    }
    free(request.Processes);
  }
  // Dump thread registers
  if (wcscmp(argv[1], L"/DumpThreadRegisters") == 0)
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
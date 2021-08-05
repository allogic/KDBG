#include "trace.h"
#include "undoc.h"

VOID
KmTraceThread(
  PVOID context)
{
  PTRACE_CONTEXT traceContext = (PTRACE_CONTEXT)context;
  NTSTATUS status = STATUS_SUCCESS;
  PCONTEXT registers = NULL;
  SIZE_T registersSize = sizeof(CONTEXT);
  ULONG count = 0;
  PETHREAD* threads = (PETHREAD*)KmAllocateMemory(TRUE, sizeof(PETHREAD) * traceContext->ThreadCount);
  if (threads != NULL)
  {
    for (ULONG i = 0; i < traceContext->ThreadCount; ++i)
    {
      status = PsLookupThreadByThreadId((HANDLE)traceContext->Threads[i].Tid, &threads[i]);
    }
    if (NT_SUCCESS(status))
    {
      status = ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID*)&registers, 0, &registersSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
      if (NT_SUCCESS(status))
      {
        while (traceContext->Running)
        {
          KM_LOG_INFO("                 Rax                  Rcx                  Rdx                  Rbx                  Rsp                  Rbp                  Rsi                  Rdi\n");
          for (ULONG i = 0; i < traceContext->ThreadCount; ++i)
          {            
            traceContext->Opcodes[count++ % 64] = count;
            memset(registers, 0, registersSize);
            registers->ContextFlags = CONTEXT_ALL;
            status = PsGetContextThread(threads[i], registers, UserMode);
            if (NT_SUCCESS(status))
            {
              KM_LOG_INFO("%20llu %20llu %20llu %20llu %20llu %20llu %20llu %20llu\n",
                registers->Rax,
                registers->Rcx,
                registers->Rdx,
                registers->Rbx,
                registers->Rsp,
                registers->Rbp,
                registers->Rsi,
                registers->Rdi);
            }
          }
          KM_LOG_INFO("\n");
          KmSleep(1000);
        }
        ZwFreeVirtualMemory(ZwCurrentProcess(), (PVOID*)registers, &registersSize, MEM_RELEASE);
      }
    }
    for (ULONG i = 0; i < traceContext->ThreadCount; ++i)
    {
      ObDereferenceObject(threads[i]);
    }
    KmFreeMemory(threads);
  }
  KeSetEvent(&traceContext->Event, IO_NO_INCREMENT, FALSE);
}
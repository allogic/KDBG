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
  PETHREAD thread = NULL;
  status = PsLookupThreadByThreadId((HANDLE)traceContext->Tid, &thread);
  if (NT_SUCCESS(status))
  {
    status = ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID*)&registers, 0, &registersSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (NT_SUCCESS(status))
    {
      while (traceContext->Running)
      {
        traceContext->Opcodes[count++ % 64] = count;
        memset(registers, 0, registersSize);
        registers->ContextFlags = CONTEXT_ALL;
        status = PsGetContextThread(thread, registers, UserMode);
        if (NT_SUCCESS(status))
        {
          KM_LOG_INFO("%10llu %10llu %10llu %10llu %10llu %10llu %10llu %10llu\n",
            registers->Rax,
            registers->Rcx,
            registers->Rdx,
            registers->Rbx,
            registers->Rsp,
            registers->Rbp,
            registers->Rsi,
            registers->Rdi);
        }
        KmSleep(50);
      }
      ZwFreeVirtualMemory(ZwCurrentProcess(), (PVOID*)registers, &registersSize, MEM_RELEASE);
    }
    ObDereferenceObject(thread);
  }
  KeSetEvent(&traceContext->Event, IO_NO_INCREMENT, FALSE);
}
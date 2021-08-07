#include "trace.h"
#include "undoc.h"

LONG
KmContainsValue(
  PULONG64 opCodes,
  ULONG opCodesCount,
  ULONG64 value)
{
  LONG index = -1;
  for (ULONG i = 0; i < opCodesCount; ++i)
  {
    if (opCodes[i] == value)
    {
      index = i;
      break;
    }
  }
  return index;
}

VOID
KmTraceThread(
  PVOID context)
{
  PTRACE_CONTEXT traceContext = (PTRACE_CONTEXT)context;
  NTSTATUS status = STATUS_SUCCESS;
  PCONTEXT registers = NULL;
  SIZE_T registersSize = sizeof(CONTEXT);
  ULONG distinctCount = 0;
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
        KM_LOG_INFO("Searching for %p\n", (PVOID)traceContext->Address);
        while (traceContext->Running)
        {
          for (ULONG i = 0; i < traceContext->ThreadCount; ++i)
          {            
            memset(registers, 0, registersSize);
            registers->ContextFlags = CONTEXT_ALL;
            status = PsGetContextThread(threads[i], registers, UserMode);
            if (NT_SUCCESS(status))
            {
              if (
                   registers->Rax == traceContext->Address
                || registers->Rcx == traceContext->Address
                || registers->Rdx == traceContext->Address
                || registers->Rbx == traceContext->Address
                || registers->Rsp == traceContext->Address
                || registers->Rbp == traceContext->Address
                || registers->Rsi == traceContext->Address
                || registers->Rdi == traceContext->Address
                || registers->R8  == traceContext->Address
                || registers->R9  == traceContext->Address
                || registers->R10 == traceContext->Address
                || registers->R11 == traceContext->Address
                || registers->R12 == traceContext->Address
                || registers->R13 == traceContext->Address
                || registers->R14 == traceContext->Address
                || registers->R15 == traceContext->Address)
              {
                LONG opCodeIndex = KmContainsValue(traceContext->OpCodes, sizeof(traceContext->OpCodes), registers->Rip);
                if (opCodeIndex == -1)
                {
                  if (distinctCount < sizeof(traceContext->OpCodes))
                  {
                    traceContext->OpCodes[distinctCount++] = registers->Rip;
                  }
                }
                else
                {
                  traceContext->OpCodes[opCodeIndex] = registers->Rip;
                }
                KM_LOG_INFO("%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p\n",
                  (PVOID)registers->Rax,
                  (PVOID)registers->Rcx,
                  (PVOID)registers->Rdx,
                  (PVOID)registers->Rbx,
                  (PVOID)registers->Rsp,
                  (PVOID)registers->Rbp,
                  (PVOID)registers->Rsi,
                  (PVOID)registers->Rdi,
                  (PVOID)registers->R8,
                  (PVOID)registers->R9,
                  (PVOID)registers->R10,
                  (PVOID)registers->R11,
                  (PVOID)registers->R12,
                  (PVOID)registers->R13,
                  (PVOID)registers->R14,
                  (PVOID)registers->R15);
                traceContext->Running = FALSE;
              }
            }
          }
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
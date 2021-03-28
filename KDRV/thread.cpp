#include "thread.h"
#include "undoc.h"

NTSTATUS SuspendThread(ULONG pid)
{
  UNREFERENCED_PARAMETER(pid);
  NTSTATUS status = STATUS_SUCCESS;
  // Open thread context
  HANDLE thread;
  OBJECT_ATTRIBUTES objectAttributes;
  memset(&objectAttributes, 0, sizeof(objectAttributes));
  CLIENT_ID clientId;
  clientId.UniqueProcess = PsGetCurrentProcessId();
  clientId.UniqueThread = PsGetCurrentThreadId();
  status = ZwOpenThread(&thread, THREAD_SUSPEND_RESUME, &objectAttributes, &clientId);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("ZwOpenThread %X\n", status);
    return status;
  }
  LOG_INFO("CurrentProcess: %p UniqueProcess: %p\n", PsGetCurrentProcessId(), clientId.UniqueProcess);
  LOG_INFO("CurrentThread: %p UniqueThread: %p\n", PsGetCurrentThreadId(), clientId.UniqueThread);
  // Suspend the thread
  status = ZwSuspendThread(thread, 0);
  if (!NT_SUCCESS(status))
  {
    
    LOG_ERROR("ZwSuspendThread %X\n", status);
    return status;
  }
  return status;
}
NTSTATUS ResumeThread(HANDLE process)
{
  UNREFERENCED_PARAMETER(process);
  NTSTATUS status = STATUS_SUCCESS;
  return status;
}
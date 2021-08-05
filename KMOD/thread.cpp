#include "thread.h"

NTSTATUS
KmGetProcessThreads(
  ULONG pid,
  ULONG* threadCount,
  PVOID threads)
{
  NTSTATUS status = STATUS_SUCCESS;
  PBYTE buffer = (PBYTE)KmAllocateMemory(TRUE, sizeof(SYSTEM_PROCESS_INFORMATION) * 1024 * 1024);
  if (buffer != NULL)
  {
    status = ZwQuerySystemInformation(SystemProcessInformation, buffer, sizeof(SYSTEM_PROCESS_INFORMATION) * 1024 * 1024, NULL);
    if (NT_SUCCESS(status))
    {
      PBYTE bytes = buffer;
      ULONG processAcc = 0;
      while (TRUE)
      {
        PSYSTEM_PROCESS_INFORMATION process = (PSYSTEM_PROCESS_INFORMATION)bytes;
        for (ULONG i = 0; i < process->NumberOfThreads; ++i)
        {
          ULONG nextThreadByteOffset = sizeof(SYSTEM_THREAD_INFORMATION) * i;
          PSYSTEM_THREAD_INFORMATION thread = (PSYSTEM_THREAD_INFORMATION)(bytes + sizeof(SYSTEM_PROCESS_INFORMATION) + nextThreadByteOffset);
          if (thread != NULL)
          {
            if (pid == (ULONG)thread->ClientId.UniqueProcess)
            {
              ((PKM_THREAD_PROCESS)threads)[*threadCount].Pid = (ULONG)thread->ClientId.UniqueProcess;
              ((PKM_THREAD_PROCESS)threads)[*threadCount].Tid = (ULONG)thread->ClientId.UniqueThread;
              (*threadCount)++;
              status = STATUS_SUCCESS;
            }
          }
        }
        if (process->NextEntryOffset == NULL)
        {
          break;
        }
        else
        {
          bytes += process->NextEntryOffset;
          processAcc++;
        }
      }
    }
    KmFreeMemory(buffer);
  }
  return status;
}

ULONG
KeForceResumeThread(
  PKTHREAD Thread)
{
  //KLOCK_QUEUE_HANDLE ApcLock;
  //ULONG PreviousCount;
  ///* Lock the APC Queue */
  //KiAcquireApcLockRaiseToSynch(Thread, &ApcLock);
  ///* Save the old Suspend Count */
  //PreviousCount = Thread->SuspendCount + Thread->FreezeCount;
  ///* If the thread is suspended, wake it up!!! */
  //if (PreviousCount)
  //{
  //  /* Unwait it completely */
  //  Thread->SuspendCount = 0;
  //  Thread->FreezeCount = 0;
  //  /* Lock the dispatcher */
  //  KiAcquireDispatcherLockAtSynchLevel();
  //  /* Signal and satisfy */
  //  Thread->SuspendSemaphore.Header.SignalState++;
  //  KiWaitTest(&Thread->SuspendSemaphore.Header, IO_NO_INCREMENT);
  //  /* Release the dispatcher */
  //  KiReleaseDispatcherLockFromSynchLevel();
  //}
  ///* Release Lock and return the Old State */
  //KiReleaseApcLockFromSynchLevel(&ApcLock);
  //KiExitDispatcher(ApcLock.OldIrql);
  //return PreviousCount;
  return 0;
}

ULONG
KeResumeThread(
  PKTHREAD Thread)
{
  //KLOCK_QUEUE_HANDLE ApcLock;
  //ULONG PreviousCount;
  ///* Lock the APC Queue */
  //KiAcquireApcLockRaiseToSynch(Thread, &ApcLock);
  ///* Save the Old Count */
  //PreviousCount = Thread->SuspendCount;
  ///* Check if it existed */
  //if (PreviousCount)
  //{
  //  /* Decrease the suspend count */
  //  Thread->SuspendCount--;
  //  /* Check if the thrad is still suspended or not */
  //  if ((!Thread->SuspendCount) && (!Thread->FreezeCount))
  //  {
  //    /* Acquire the dispatcher lock */
  //    KiAcquireDispatcherLockAtSynchLevel();
  //    /* Signal the Suspend Semaphore */
  //    Thread->SuspendSemaphore.Header.SignalState++;
  //    KiWaitTest(&Thread->SuspendSemaphore.Header, IO_NO_INCREMENT);
  //    /* Release the dispatcher lock */
  //    KiReleaseDispatcherLockFromSynchLevel();
  //  }
  //}
  ///* Release APC Queue lock and return the Old State */
  //KiReleaseApcLockFromSynchLevel(&ApcLock);
  //KiExitDispatcher(ApcLock.OldIrql);
  //return PreviousCount;
  return 0;
}
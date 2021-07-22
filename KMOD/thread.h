#ifndef _THREAD_H
#define _THREAD_H

#include "global.h"
#include "krnl.h"

/*
* Thread utilities.
*/

typedef struct _SYSTEM_THREAD_INFORMATION
{
  LARGE_INTEGER KernelTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER CreateTime;
  ULONG WaitTime;
  PVOID StartAddress;
  CLIENT_ID ClientId;
  LONG Priority;
  LONG BasePriority;
  ULONG ContextSwitches;
  ULONG ThreadState;
  ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef NTSTATUS(*PSGETCONTEXTTHREAD)(
  PETHREAD Thread,
  PCONTEXT ThreadContext,
  KPROCESSOR_MODE Mode);
typedef NTSTATUS(*PSSETCONTEXTTHREAD)(
  PETHREAD Thread,
  PCONTEXT ThreadContext,
  KPROCESSOR_MODE Mode);

NTSTATUS PsGetContextThread(
  PETHREAD Thread,
  PCONTEXT ThreadContext,
  KPROCESSOR_MODE Mode);
NTSTATUS PsSetContextThread(
  PETHREAD Thread,
  PCONTEXT ThreadContext,
  KPROCESSOR_MODE Mode);

//ULONG KeForceResumeThread(PKTHREAD Thread)
//{
//  KLOCK_QUEUE_HANDLE ApcLock;
//  ULONG PreviousCount;
//  /* Lock the APC Queue */
//  KiAcquireApcLockRaiseToSynch(Thread, &ApcLock);
//  /* Save the old Suspend Count */
//  PreviousCount = Thread->SuspendCount + Thread->FreezeCount;
//  /* If the thread is suspended, wake it up!!! */
//  if (PreviousCount)
//  {
//    /* Unwait it completely */
//    Thread->SuspendCount = 0;
//    Thread->FreezeCount = 0;
//    /* Lock the dispatcher */
//    KiAcquireDispatcherLockAtSynchLevel();
//    /* Signal and satisfy */
//    Thread->SuspendSemaphore.Header.SignalState++;
//    KiWaitTest(&Thread->SuspendSemaphore.Header, IO_NO_INCREMENT);
//    /* Release the dispatcher */
//    KiReleaseDispatcherLockFromSynchLevel();
//  }
//  /* Release Lock and return the Old State */
//  KiReleaseApcLockFromSynchLevel(&ApcLock);
//  KiExitDispatcher(ApcLock.OldIrql);
//  return PreviousCount;
//}
//ULONG KeResumeThread(PKTHREAD Thread)
//{
//  KLOCK_QUEUE_HANDLE ApcLock;
//  ULONG PreviousCount;
//  /* Lock the APC Queue */
//  KiAcquireApcLockRaiseToSynch(Thread, &ApcLock);
//  /* Save the Old Count */
//  PreviousCount = Thread->SuspendCount;
//  /* Check if it existed */
//  if (PreviousCount)
//  {
//    /* Decrease the suspend count */
//    Thread->SuspendCount--;
//    /* Check if the thrad is still suspended or not */
//    if ((!Thread->SuspendCount) && (!Thread->FreezeCount))
//    {
//      /* Acquire the dispatcher lock */
//      KiAcquireDispatcherLockAtSynchLevel();
//      /* Signal the Suspend Semaphore */
//      Thread->SuspendSemaphore.Header.SignalState++;
//      KiWaitTest(&Thread->SuspendSemaphore.Header, IO_NO_INCREMENT);
//      /* Release the dispatcher lock */
//      KiReleaseDispatcherLockFromSynchLevel();
//    }
//  }
//  /* Release APC Queue lock and return the Old State */
//  KiReleaseApcLockFromSynchLevel(&ApcLock);
//  KiExitDispatcher(ApcLock.OldIrql);
//  return PreviousCount;
//}

VOID DumpContext(PCONTEXT context);

#endif
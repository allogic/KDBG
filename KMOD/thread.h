#ifndef _THREAD_H
#define _THREAD_H

#include "global.h"
#include "undoc.h"

/*
* Thread utilities.
*/

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

#endif
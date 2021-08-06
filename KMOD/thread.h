/*
* @author allogic
* @file thread.h
* @brief Thread utilities.
* @copyright allogic 2021. All Rights Reserved.
*/

#ifndef _THREAD_H
#define _THREAD_H

#include "global.h"
#include "undoc.h"
#include "common.h"

/*
* Thread utilities.
*/

NTSTATUS
KmGetProcessThreads(
  ULONG pid,
  ULONG* threadCount,
  PVOID threads);

ULONG
KeForceResumeThread(
  PKTHREAD Thread);

ULONG
KeResumeThread(
  PKTHREAD Thread);

#endif
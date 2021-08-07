/*
* @author allogic
* @file trace.h
* @brief OpCode tracing utilities.
* @copyright allogic 2021. All Rights Reserved.
*/

#ifndef _TRACE_H
#define _TRACE_H

#include "global.h"
#include "common.h"

/*
* Trace thread utilities.
*/

typedef struct _TRACE_CONTEXT
{
  HANDLE Thread;
  ULONG Id;
  ULONG Pid;
  ULONG ThreadCount;
  KM_THREAD_PROCESS Threads[1024];
  ULONG64 Address;
  BOOL Running;
  KEVENT Event;
  ULONG64 OpCodes[64];
} TRACE_CONTEXT, * PTRACE_CONTEXT;

LONG
KmContainsValue(
  PULONG64 opCodes,
  ULONG opCodesCount,
  ULONG64 value);

VOID
KmTraceThread(
  PVOID context);

#endif
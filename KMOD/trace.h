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
  HANDLE Thread = NULL;
  ULONG Id = 0;
  ULONG Pid = 0;
  ULONG ThreadCount = 0;
  KM_THREAD_PROCESS Threads[1024] = {};
  ULONG64 Address = 0;
  BOOL Running = TRUE;
  KEVENT Event = {};
  ULONG64 Opcodes[64] = {};
} TRACE_CONTEXT, * PTRACE_CONTEXT;

VOID
KmTraceThread(
  PVOID context);

#endif
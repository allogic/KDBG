#ifndef _TRACE_H
#define _TRACE_H

#include "global.h"
#include "common.h"
#include "undoc.h"

/*
* Stack frames.
*/

typedef struct _STACK_FRAME_X64
{
  ULONG64 AddrOffset;
  ULONG64 StackOffset;
  ULONG64 FrameOffset;
} STACK_FRAME_X64, * PSTACK_FRAME_X64;

/*
* Tracing utilities.
*/

VOID
KmTraceContext(
  HANDLE tid,
  SIZE_T iterations);

VOID
KmTraceStack(
  HANDLE pid,
  HANDLE tid,
  PWCHAR moduleName,
  SIZE_T iterations);

#endif
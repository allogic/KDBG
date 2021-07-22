#ifndef _COMMON_H
#define _COMMON_H

#include "global.h"

/*
* Common request types.
*/

#define KMOD_MAX_MODULES 128
#define KMOD_MAX_THREADS 128

typedef struct _MODULE
{
  WCHAR Name[256] = {};
  ULONG64 Base = 0;
  SIZE_T Size = 0;
} MODULE, * PMODULE;
typedef struct _THREAD
{
  ULONG Tid = 0;
  ULONG Pid = 0;
} THREAD, * PTHREAD;

#endif
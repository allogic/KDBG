#ifndef _WDK_H
#define _WDK_H

#include "global.h"

typedef struct _UNICODE_STRING
{
  USHORT Length;
  USHORT MaximumLength;
} UNICODE_STRING;

typedef LONG KPRIORITY;

typedef struct _CLIENT_ID
{
  HANDLE UniqueProcess;
  HANDLE UniqueThread;
} CLIENT_ID;

#endif
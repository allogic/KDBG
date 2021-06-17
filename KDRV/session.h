#ifndef _SESSION_H
#define _SESSION_H

#include "global.h"

typedef struct _KDRV_KERNEL_SESSION
{
  HANDLE Thread;
  PDEVICE_OBJECT Device;
} KDRV_KERNEL_SESSION, * PKDRV_KERNEL_SESSION;
typedef struct _KDRV_USER_SESSION
{
  HANDLE Thread;
  PDEVICE_OBJECT Device;
  PEPROCESS Process;
  ULONG Pid;
} KDRV_USER_SESSION, * PKDRV_USER_SESSION;

#endif
#ifndef _THREAD_H
#define _THREAD_H

#include "global.h"

NTSTATUS SuspendThread(ULONG pid);
NTSTATUS ResumeThread(HANDLE process);

#endif
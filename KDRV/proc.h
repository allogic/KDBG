#ifndef _SYSTEM_H
#define _SYSTEM_H

#include "global.h"
#include "undoc.h"

NTSTATUS GetUserImages(PSYSTEM_PROCESS_INFORMATION images, ULONG size);
NTSTATUS GetUserImageModules(ULONG pid, PRTL_PROCESS_MODULES modules, ULONG size);
NTSTATUS GetUserImageThreads(ULONG pid, PSYSTEM_THREAD_INFORMATION images, ULONG size);

#endif
#ifndef _SYSTEM_H
#define _SYSTEM_H

#include "global.h"
#include "undoc.h"
#include "pe.h"
#include "ioctrl.h"
#include "mem.h"

VOID GetKernelImages(PKDRV_REQ_DUMP_KRNL_IMAGES request, BOOL verbose = FALSE);
VOID GetUserProcesses(PKDRV_REQ_DUMP_PROCESSES request, BOOL verbose = FALSE);

PVOID GetKernelModuleBase(PCHAR moduleName);
PVOID GetUserModuleBase(PEPROCESS process, PWCHAR moduleName);

#endif
#ifndef _SYSTEM_H
#define _SYSTEM_H

#include "global.h"
#include "undoc.h"
#include "pe.h"
#include "ioctrl.h"
#include "mem.h"

VOID GetKernelModules(PKDRV_REQ_DUMP_MODULES request, BOOL verbose = FALSE);
VOID GetUserModules(PEPROCESS process, PKDRV_REQ_DUMP_MODULES request, BOOL verbose = FALSE);

PVOID GetKernelModuleBase(PCHAR moduleName);
PVOID GetUserModuleBase(PEPROCESS process, PWCHAR moduleName);

#endif
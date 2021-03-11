#ifndef _UTIL_H
#define _UTIL_H

#include "global.h"

NTSTATUS DriverSleep(int ms);
PVOID SanitizeUserPointer(PVOID pointer, SIZE_T size);

#endif
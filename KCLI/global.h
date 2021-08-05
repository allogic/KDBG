#ifndef _GLOBAL_H
#define _GLOBAL_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <minwindef.h>

typedef double DOUBLE;

#include <tlhelp32.h>
#include <winioctl.h>

#include <stdlib.h>
#include <stdio.h>

#include <capstone/capstone.h>
#include <capstone/platform.h>

/*
* Logging utilities.
*/

#define _KCLI_STR(VAL) #VAL
#define KCLI_STR(VAL) _KCLI_STR(VAL)

#define KC_LOG_INFO(FMT, ...) printf("[+] " FMT, __VA_ARGS__)
#define KC_LOG_ERROR(FMT, ...) printf("[-] " FMT, __VA_ARGS__)

#endif
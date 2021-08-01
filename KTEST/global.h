#ifndef _GLOBAL_H
#define _GLOBAL_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <winioctl.h>

#include <tlhelp32.h>

/*
* Standard library.
*/

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <codecvt>

/*
* Logging utilities.
*/

#define _KCLI_STR(VAL) #VAL
#define KCLI_STR(VAL) _KCLI_STR(VAL)

#define KC_LOG_INFO(FMT, ...) printf("[+] " FMT, __VA_ARGS__)
#define KC_LOG_ERROR(FMT, ...) printf("[-] " FMT, __VA_ARGS__)

#endif
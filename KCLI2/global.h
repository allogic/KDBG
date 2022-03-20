#ifndef GLOBAL_H
#define GLOBAL_H

#include <stdlib.h>
#include <stdio.h>

#include <windows.h>
#include <tlhelp32.h>
#include <winioctl.h>

/*
* Missing types
*/

typedef long long unsigned LWORD;

/*
* Logging utils
*/

#define KC_LOG_INFO(FMT, ...) printf("[+] " FMT, __VA_ARGS__)
#define KC_LOG_ERROR(FMT, ...) printf("[-] " FMT, __VA_ARGS__)

#endif
#ifndef _GLOBAL_H
#define _GLOBAL_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <windows.h>
#include <tlhelp32.h>

#ifdef __cplusplus
}
#endif

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>

#include <capstone/capstone.h>
#include <capstone/platform.h>

#define _STR(VAL) #VAL
#define STR(VAL) _STR(VAL)

#define LOG_INFO(MSG, ...) printf("[+] " MSG, __VA_ARGS__)
#define LOG_ERROR(MSG, ...) printf("[-] " MSG, __VA_ARGS__)

#endif
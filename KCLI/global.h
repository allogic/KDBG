#ifndef _GLOBAL_H
#define _GLOBAL_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>

#ifdef __cplusplus
}
#endif

#include <capstone/capstone.h>
#include <capstone/platform.h>

#define _STR(VAL) #VAL
#define STR(VAL) _STR(VAL)

#define LOG_INFO(MSG, ...) DbgPrintEx(0, 0, "[+] " MSG, __VA_ARGS__)
#define LOG_ERROR(MSG, ...) DbgPrintEx(0, 0, "[-] " MSG, __VA_ARGS__)

#define LOG_ENTER_FUNCTION(CLASS, FUNCTION) DbgPrintEx(0, 0, "[>] " STR(CLASS) "::" STR(FUNCTION) "\n")
#define LOG_EXIT_FUNCTION(CLASS, FUNCTION) DbgPrintEx(0, 0, "[<] " STR(CLASS) "::" STR(FUNCTION) "\n")

#endif
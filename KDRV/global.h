#ifndef _GLOBAL_H
#define _GLOBAL_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>

#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>

#include <windef.h>

#ifdef __cplusplus
}
#endif

typedef PCHAR * PPCHAR;
typedef PVOID * PPVOID;

#define _STR(VAL) #VAL
#define STR(VAL) _STR(VAL)

#define LOG_INFO(MSG, ...) DbgPrintEx(0, 0, "[+] " MSG, __VA_ARGS__)
#define LOG_ERROR(MSG, ...) DbgPrintEx(0, 0, "[-] " MSG, __VA_ARGS__)

#define LOG_ENTER_FUNCTION(CLASS, FUNCTION) DbgPrintEx(0, 0, "[>] " STR(CLASS) "::" STR(FUNCTION) "\n")
#define LOG_EXIT_FUNCTION(CLASS, FUNCTION) DbgPrintEx(0, 0, "[<] " STR(CLASS) "::" STR(FUNCTION) "\n")

ULONG RtlNextRandom(ULONG min, ULONG max);
ULONG GetPoolTag();

PVOID RtlAllocateMemory(BOOL zeroMemory, SIZE_T size);
VOID RtlFreeMemory(PVOID pointer);

#endif
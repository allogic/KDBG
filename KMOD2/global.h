#ifndef GLOBAL_H
#define GLOBAL_H

#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <stddef.h>
#include <windef.h>

/*
* Missing types
*/

typedef long long unsigned LWORD;

/*
* Some random
*/

ULONG
KmNextRandom(
  ULONG min,
  ULONG max);

/*
* Kernel malloc/free
*/

ULONG
KmNextPoolTag();

PVOID
KmAllocMemory(
  BOOL zeroMemory,
  SIZE_T size);

VOID
KmFreeMemory(
  PVOID ptr);

/*
* Timing stuff
*/

#define KM_DELAY_ONE_MICROSECOND (-10)
#define KM_DELAY_ONE_MILLISECOND (KM_DELAY_ONE_MICROSECOND*1000)

VOID
KmSleep(
  LONG ms);

/*
* Logging utils
*/

#define KM_LOG_INFO(FMT, ...) DbgPrintEx(0, 0, "[+] " FMT, __VA_ARGS__)
#define KM_LOG_ERROR(FMT, ...) DbgPrintEx(0, 0, "[-] " FMT, __VA_ARGS__)

#define KM_LOG_ENTER_FUNCTION(CLASS, FUNCTION) DbgPrintEx(0, 0, "[>] " #CLASS "::" #FUNCTION "\n")
#define KM_LOG_EXIT_FUNCTION(CLASS, FUNCTION) DbgPrintEx(0, 0, "[<] " #CLASS "::" #FUNCTION "\n")

#endif
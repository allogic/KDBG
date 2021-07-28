#ifndef _GLOBAL_H
#define _GLOBAL_H

#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>

#include <stddef.h>
#include <windef.h>

#include <wsk.h>

#define _KM_STR(VAL) #VAL
#define KM_STR(VAL) _KM_STR(VAL)

/*
* Standard library.
*/

static ULONG Seed = 0;

static ULONG KmNextRandom(ULONG min, ULONG max)
{
  Seed = (ULONG)__rdtsc();
  const ULONG scale = (ULONG)MAXINT32 / (max - min);
  return RtlRandomEx(&Seed) / scale + min;
}
static ULONG KmNextPoolTag()
{
  static ULONG poolTags[] =
  {
    ' prI', // Allocated IRP packets
    '+prI', // I/O verifier allocated IRP packets
    'eliF', // File objects
    'atuM', // Mutant objects
    'sFtN', // ntfs.sys!StrucSup.c
    'ameS', // Semaphore objects
    'RwtE', // Etw KM RegEntry
    'nevE', // Event objects
    ' daV', // Mm virtual address descriptors
    'sdaV', // Mm virtual address descriptors (short)
    'aCmM', // Mm control areas for mapped files
    '  oI', // I/O manager
    'tiaW', // WaitCompletion Packets
    'eSmM', // Mm secured VAD allocation
    'CPLA', // ALPC port objects
    'GwtE', // ETW GUID
    ' ldM', // Memory Descriptor Lists
    'erhT', // Thread objects
    'cScC', // Cache Manager Shared Cache Map
    'KgxD', // Vista display driver support
  };
  static ULONG numPoolTags = ARRAYSIZE(poolTags);
  const ULONG index = KmNextRandom(0, numPoolTags);
  NT_ASSERT(index <= numPoolTags - 1);
  return index;
}

static PVOID KmAllocateMemory(BOOL zeroMemory, SIZE_T size)
{
  PVOID ptr = ExAllocatePoolWithTag(NonPagedPool, size, KmNextPoolTag());
  if (zeroMemory && ptr)
    RtlZeroMemory(ptr, size);
  return ptr;
}
static VOID KmFreeMemory(PVOID ptr)
{
  ExFreePool(ptr);
}

#define DELAY_ONE_MICROSECOND 	(-10)
#define DELAY_ONE_MILLISECOND	(DELAY_ONE_MICROSECOND*1000)

static VOID KmSleep(LONG ms)
{
  LARGE_INTEGER interval;
  interval.QuadPart = DELAY_ONE_MILLISECOND;
  interval.QuadPart *= ms;
  KeDelayExecutionThread(KernelMode, 0, &interval);
}

/*
* Logging utilities.
*/

#define KM_LOG_INFO(FMT, ...) DbgPrintEx(0, 0, "[+] " FMT, __VA_ARGS__)
#define KM_LOG_ERROR(FMT, ...) DbgPrintEx(0, 0, "[-] " FMT, __VA_ARGS__)

#define KM_LOG_ENTER_FUNCTION(CLASS, FUNCTION) DbgPrintEx(0, 0, "[>] " KM_STR(CLASS) "::" KM_STR(FUNCTION) "\n")
#define KM_LOG_EXIT_FUNCTION(CLASS, FUNCTION) DbgPrintEx(0, 0, "[<] " KM_STR(CLASS) "::" KM_STR(FUNCTION) "\n")

#endif
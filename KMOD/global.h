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

#define _KMOD_STR(VAL) #VAL
#define KMOD_STR(VAL) _KMOD_STR(VAL)

/*
* Standard library.
*/

static ULONG Seed = 0;

static ULONG RtlNextRandom(ULONG min, ULONG max)
{
  Seed = (ULONG)__rdtsc();
  const ULONG scale = (ULONG)MAXINT32 / (max - min);
  return RtlRandomEx(&Seed) / scale + min;
}
static ULONG GetNextPoolTag()
{
  constexpr ULONG poolTags[] =
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
  constexpr ULONG numPoolTags = ARRAYSIZE(poolTags);
  const ULONG index = RtlNextRandom(0, numPoolTags);
  NT_ASSERT(index <= numPoolTags - 1);
  return index;
}

static PVOID RtlAllocateMemory(BOOL zeroMemory, SIZE_T size)
{
  PVOID ptr = ExAllocatePoolWithTag(NonPagedPool, size, GetNextPoolTag());
  if (zeroMemory && ptr)
    RtlZeroMemory(ptr, size);
  return ptr;
}
static VOID RtlFreeMemory(PVOID ptr)
{
  ExFreePool(ptr);
}

/*
* Logging utilities.
*/

#define KMOD_LOG_INFO(FMT, ...) DbgPrintEx(0, 0, "[+] " FMT, __VA_ARGS__)
#define KMOD_LOG_ERROR(FMT, ...) DbgPrintEx(0, 0, "[-] " FMT, __VA_ARGS__)

#define KMOD_LOG_ENTER_FUNCTION(CLASS, FUNCTION) DbgPrintEx(0, 0, "[>] " KMOD_STR(CLASS) "::" KMOD_STR(FUNCTION) "\n")
#define KMOD_LOG_EXIT_FUNCTION(CLASS, FUNCTION) DbgPrintEx(0, 0, "[<] " KMOD_STR(CLASS) "::" KMOD_STR(FUNCTION) "\n")

#endif
#include "global.h"

ULONG
KmNextRandom(
  ULONG min,
  ULONG max)
{
  ULONG seed = (ULONG)__rdtsc();
  ULONG scale = (ULONG)MAXINT32 / (max - min);
  return RtlRandomEx(&seed) / scale + min;
}

ULONG
KmNextPoolTag()
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
  ULONG index = KmNextRandom(0, numPoolTags);
  return poolTags[index];
}

PVOID
KmAllocMemory(
  BOOL zeroMemory,
  SIZE_T size)
{
  PVOID ptr = ExAllocatePoolWithTag(NonPagedPool, size, KmNextPoolTag());
  if (zeroMemory && ptr)
  {
    RtlZeroMemory(ptr, size);
  }
  return ptr;
}

VOID
KmFreeMemory(
  PVOID ptr)
{
  ExFreePool(ptr);
}

VOID
KmSleep(
  LONG ms)
{
  LARGE_INTEGER interval;
  interval.QuadPart = KM_DELAY_ONE_MILLISECOND;
  interval.QuadPart *= ms;
  KeDelayExecutionThread(KernelMode, 0, &interval);
}
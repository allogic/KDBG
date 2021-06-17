#include "global.h"

ULONG sRandomSeed = 0;

ULONG RtlNextRandom(ULONG min, ULONG max)
{
  sRandomSeed = (ULONG)__rdtsc();
  const ULONG scale = (ULONG)MAXINT32 / (max - min);
  return RtlRandomEx(&sRandomSeed) / scale + min;
}
ULONG GetNextPoolTag()
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

PVOID RtlAllocateMemory(BOOL zeroMemory, SIZE_T size)
{
  PVOID ptr = ExAllocatePoolWithTag(NonPagedPool, size, GetNextPoolTag());
  if (zeroMemory && ptr)
    RtlZeroMemory(ptr, size);
  return ptr;
}
VOID RtlFreeMemory(PVOID ptr)
{
  ExFreePool(ptr);
}

NTSTATUS DriverSleep(LONGLONG ms)
{
  LARGE_INTEGER li;
  li.QuadPart = -ms;
  return KeDelayExecutionThread(KernelMode, FALSE, &li);
}
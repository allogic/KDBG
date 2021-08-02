#include "allocator.h"

constexpr long unsigned PoolTags[] =
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
constexpr long unsigned PoolTagsCount = sizeof(PoolTags);

void* operator new (size_t size)
{
  long unsigned tag = PoolTags[NextBetween(0, PoolTagsCount)];
  void* ptr = ExAllocatePoolWithTag(NonPagedPool, size, tag);
  if (ptr)
  {
    memset(ptr, 0, size);
  }
  return ptr;
}
void* operator new[] (size_t size)
{
  long unsigned tag = PoolTags[NextBetween(0, PoolTagsCount)];
  void* ptr = ExAllocatePoolWithTag(NonPagedPool, size, tag);
  if (ptr)
  {
    memset(ptr, 0, size);
  }
  return ptr;
}

void operator delete (void* ptr)
{
  if (ptr)
  {
    ExFreePool(ptr);
  }
}
void operator delete[] (void* ptr)
{
  if (ptr)
  {
    ExFreePool(ptr);
  }
}

/*
Header:
hidApi.h
[PHP]
#ifndef HIDAPI_H_
#define HIDAPI_H_

#include "ntddk.h"
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
  ULONG SystemInformationClass,
  PVOID SystemInformation,
  ULONG SystemInformationLength,
  PULONG ReturnLength
);

#endif
[/ PHP]winstructs.h : I took some of these structs from a website which lists undocumented structs& members
[PHP]
#ifndef WINSTRUCTS_H_
#define WINSTRUCTS_H_
#include "ntddk.h"
typedef struct _SYSTEM_THREADS

{
  LARGE_INTEGER KernelTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER CreateTime;
  ULONG WaitTime;
  PVOID StartAddress;
  CLIENT_ID ClientId;
  KPRIORITY Priority;
  KPRIORITY BasePriority;
  ULONG ContextSwitchCount;
  ULONG ThreadState;
  KWAIT_REASON WaitReason;
} _SYSTEM_THREADS;


typedef struct _SYSTEM_PROCESSES
{
  ULONG NextEntry;
  ULONG ThreadCount;
  ULONG Reserved[6];
  LARGE_INTEGER CreateTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER KernelTime;
  UNICODE_STRING ProcessName;
  KPRIORITY BasePriority;
  ULONG ProcessId;
  ULONG InheritedFromProcessId;
  ULONG HandleCount;
  ULONG Reserved2[2];
  VM_COUNTERS VmCounters;
  IO_COUNTERS IoCounters;
  _SYSTEM_THREADS Threads[1];
} _SYSTEM_PROCESSES;
#endif
[/ PHP]memory.h
[PHP]
#ifndef MEMORY_H_
#define MEMORY_H_

void* allocateMemory(unsigned long size);
void* allocateMemoryEx(unsigned long size, short forced);

void freeMemoryPool(void* addr);

#endif
[/ PHP]
systemInformation.h
[PHP]
#ifndef SYSTEMINFORMATION_H_
#define SYSTEMINFORMATION_H_
#include "ntddk.h"

/* If ALLOW_BUFFER_ALLOCATION_RAISED is defined, buffers are allowed to exceed their fixed limit to provide a larger buffer, which may
* be required for API calls that require a buffer with an unknown and varying required size. Regardless if this is defined or not,
* BUFFER_INCREASE_PER_CYCLE must be defined.
#define ALLOW_BUFFER_ALLOCATION_RAISED
#define BUFFER_INCREASE_PER_CYCLE 0x200 //When buffer size is not large enough, it will be increased by this amount.
#define ALLOW_MUST_SUCCEED_ALLOCATIONS 1 //Dangerous and could cause system crashes on systems with low resources. However if the buffer isn't huge, it is safe. I have to use it on my VM because of it's low amount of virtual ram.
#define SYS_INFO_PROCESSES_SIZE 0x8000
#define SystemProcessesAndThreadsInformation 5 //I had an enumerator here for all the members of, but to strip down code, I replaced it with the single required definition. If you need a list of these, they should be listed in any webpage that discuss undocumented kernel APIs.

HANDLE GetProcHandle(PWCHAR procName);

#endif
[/ PHP]memory.c
[PHP]
#include "ntddk.h"
#include "memory.h"

void* allocateMemory(unsigned long size)
{
  return (void*)ExAllocatePool(NonPagedPool, size);
}

void* allocateMemoryEx(unsigned long size, short forced)
{
  return (void*)ExAllocatePool(NonPagedPool | (forced ? NonPagedPoolMustSucceed : 0), size);
}

void freeMemoryPool(void* addr)
{
  ExFreePool(addr);
}
[/ PHP]systemInformation.c
[PHP]
#include "winstructs.h"
#include "memory.h"
#include "ntddk.h"
#include "hidApi.h"
#include "systemInformation.h"


HANDLE GetProcHandle(PWCHAR procName)
{

  NTSTATUS status;
  _SYSTEM_PROCESSES* sysProcInfo;
  UNICODE_STRING usTgtBuffer;
  HANDLE hHandleBuffer;
  OBJECT_ATTRIBUTES objAttrib;

  void* allocationBase;
  unsigned long bufSize;

  bufSize = SYS_INFO_PROCESSES_SIZE;

  RtlInitUnicodeString(&usTgtBuffer, procName);

  do
  {

    allocationBase = (_SYSTEM_PROCESSES*)allocateMemoryEx(bufSize, ALLOW_MUST_SUCCEED_ALLOCATIONS);

    if (!allocationBase)
      return 0;

    status = ZwQuerySystemInformation(SystemProcessesAndThreads Information, allocationBase, bufSize, 0);

    if (status == STATUS_INFO_LENGTH_MISMATCH)
    {
      freeMemoryPool(allocationBase);

#ifdef ALLOW_BUFFER_ALLOCATION_RAISED
      bufSize += BUFFER_INCREASE_PER_CYCLE;
#else
      continue;
#endif
    }
    else if (!NT_SUCCESS(status))
      return 0;

  } while (status == STATUS_INFO_LENGTH_MISMATCH);

  status = STATUS_UNSUCCESSFUL;
  sysProcInfo = (_SYSTEM_PROCESSES*)allocationBase;
  while (TRUE)
  {
    if (!RtlCompareUnicodeString(&usTgtBuffer, &sysProcInfo->ProcessName, TRUE))
    {
      if ((unsigned long)sysProcInfo->ThreadCount != 0)
      {
        InitializeObjectAttributes(&objAttrib, 0, OBJ_KERNEL_HANDLE, 0, 0);
        status = ZwOpenProcess(&hHandleBuffer, PROCESS_ALL_ACCESS, &objAttrib, &sysProcInfo->Threads[0].ClientId);
        break;
      }
      else
        break;
    }

    if (sysProcInfo->NextEntry)
      (unsigned long)sysProcInfo += (unsigned long)sysProcInfo->NextEntry;
    else
      break;
  }

  freeMemoryPool(allocationBase);

  return (NT_SUCCESS(status) ? hHandleBuffer : 0);

}
[/ PHP]
*/
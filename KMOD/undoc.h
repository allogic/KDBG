#ifndef _KRNL_H
#define _KRNL_H

#include "global.h"

/*
* Kernel utilities.
*/

template<typename FUNCTION>
static FUNCTION KmGetSystemRoutine(PCWCHAR procName)
{
  static FUNCTION functionPointer = NULL;
  if (!functionPointer)
  {
    UNICODE_STRING functionName;
    RtlInitUnicodeString(&functionName, procName);
    functionPointer = (FUNCTION)MmGetSystemRoutineAddress(&functionName);
    if (!functionPointer)
    {
      KM_LOG_ERROR("MmGetSystemRoutineAddress\n");
      return NULL;
    }
  }
  return functionPointer;
}

/*
* Kernel structs and enums.
*/

typedef enum _SYSTEM_INFORMATION_CLASS
{
  SystemBasicInformation = 0,
  SystemProcessorInformation = 1,
  SystemPerformanceInformation = 2,
  SystemTimeOfDayInformation = 3,
  SystemPathInformation = 4,
  SystemProcessInformation = 5,
  SystemCallCountInformation = 6,
  SystemDeviceInformation = 7,
  SystemProcessorPerformanceInformation = 8,
  SystemFlagsInformation = 9,
  SystemCallTimeInformation = 10,
  SystemModuleInformation = 11,
  SystemLocksInformation = 12,
  SystemStackTraceInformation = 13,
  SystemPagedPoolInformation = 14,
  SystemNonPagedPoolInformation = 15,
  SystemHandleInformation = 16,
  SystemObjectInformation = 17,
  SystemPageFileInformation = 18,
  SystemVdmInstemulInformation = 19,
  SystemVdmBopInformation = 20,
  SystemFileCacheInformation = 21,
  SystemPoolTagInformation = 22,
  SystemInterruptInformation = 23,
  SystemDpcBehaviorInformation = 24,
  SystemFullMemoryInformation = 25,
  SystemLoadGdiDriverInformation = 26,
  SystemUnloadGdiDriverInformation = 27,
  SystemTimeAdjustmentInformation = 28,
  SystemSummaryMemoryInformation = 29,
  SystemMirrorMemoryInformation = 30,
  SystemPerformanceTraceInformation = 31,
  SystemObsolete0 = 32,
  SystemExceptionInformation = 33,
  SystemCrashDumpStateInformation = 34,
  SystemKernelDebuggerInformation = 35,
  SystemContextSwitchInformation = 36,
  SystemRegistryQuotaInformation = 37,
  SystemExtendServiceTableInformation = 38,
  SystemPrioritySeperation = 39,
  SystemVerifierAddDriverInformation = 40,
  SystemVerifierRemoveDriverInformation = 41,
  SystemProcessorIdleInformation = 42,
  SystemLegacyDriverInformation = 43,
  SystemCurrentTimeZoneInformation = 44,
  SystemLookasideInformation = 45,
  SystemTimeSlipNotification = 46,
  SystemSessionCreate = 47,
  SystemSessionDetach = 48,
  SystemSessionInformation = 49,
  SystemRangeStartInformation = 50,
  SystemVerifierInformation = 51,
  SystemVerifierThunkExtend = 52,
  SystemSessionProcessInformation = 53,
  SystemLoadGdiDriverInSystemSpace = 54,
  SystemNumaProcessorMap = 55,
  SystemPrefetcherInformation = 56,
  SystemExtendedProcessInformation = 57,
  SystemRecommendedSharedDataAlignment = 58,
  SystemComPlusPackage = 59,
  SystemNumaAvailableMemory = 60,
  SystemProcessorPowerInformation = 61,
  SystemEmulationBasicInformation = 62,
  SystemEmulationProcessorInformation = 63,
  SystemExtendedHandleInformation = 64,
  SystemLostDelayedWriteInformation = 65,
  SystemBigPoolInformation = 66,
  SystemSessionPoolTagInformation = 67,
  SystemSessionMappedViewInformation = 68,
  SystemHotpatchInformation = 69,
  SystemObjectSecurityMode = 70,
  SystemWatchdogTimerHandler = 71,
  SystemWatchdogTimerInformation = 72,
  SystemLogicalProcessorInformation = 73,
  SystemWow64SharedInformation = 74,
  SystemRegisterFirmwareTableInformationHandler = 75,
  SystemFirmwareTableInformation = 76,
  SystemModuleInformationEx = 77,
  SystemVerifierTriageInformation = 78,
  SystemSuperfetchInformation = 79,
  SystemMemoryListInformation = 80,
  SystemFileCacheInformationEx = 81,
  MaxSystemInfoClass = 82,
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
  ULONG NextEntryOffset;
  ULONG NumberOfThreads;
  LARGE_INTEGER SpareLi1;
  LARGE_INTEGER SpareLi2;
  LARGE_INTEGER SpareLi3;
  LARGE_INTEGER CreateTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER KernelTime;
  UNICODE_STRING ImageName;
  KPRIORITY BasePriority;
  HANDLE UniqueProcessId;
  HANDLE InheritedFromUniqueProcessId;
  ULONG HandleCount;
  ULONG SessionId;
  ULONG_PTR PageDirectoryBase;
  SIZE_T PeakVirtualSize;
  SIZE_T VirtualSize;
  ULONG PageFaultCount;
  SIZE_T PeakWorkingSetSize;
  SIZE_T WorkingSetSize;
  SIZE_T QuotaPeakPagedPoolUsage;
  SIZE_T QuotaPagedPoolUsage;
  SIZE_T QuotaPeakNonPagedPoolUsage;
  SIZE_T QuotaNonPagedPoolUsage;
  SIZE_T PagefileUsage;
  SIZE_T PeakPagefileUsage;
  SIZE_T PrivatePageCount;
  LARGE_INTEGER ReadOperationCount;
  LARGE_INTEGER WriteOperationCount;
  LARGE_INTEGER OtherOperationCount;
  LARGE_INTEGER ReadTransferCount;
  LARGE_INTEGER WriteTransferCount;
  LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;
typedef struct _PEB_LDR_DATA
{
  ULONG Length;
  BOOLEAN Initialized;
  PVOID SsHandler;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
  PVOID EntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
typedef struct _LDR_DATA_TABLE_ENTRY
{
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  CHAR Reserved0[0x10];
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
typedef struct _PEB64 {
  CHAR Reserved[0x10];
  PVOID ImageBaseAddress;
  PPEB_LDR_DATA Ldr;
} PEB64, * PPEB64;
typedef struct _SYSTEM_THREAD_INFORMATION
{
  LARGE_INTEGER KernelTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER CreateTime;
  ULONG WaitTime;
  PVOID StartAddress;
  CLIENT_ID ClientId;
  LONG Priority;
  LONG BasePriority;
  ULONG ContextSwitches;
  ULONG ThreadState;
  ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
  HANDLE Section;
  PVOID MappedBase;
  PVOID ImageBase;
  ULONG ImageSize;
  ULONG Flags;
  USHORT LoadOrderIndex;
  USHORT InitOrderIndex;
  USHORT LoadCount;
  USHORT OffsetToFileName;
  UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;
typedef struct _RTL_PROCESS_MODULES
{
  ULONG NumberOfModules;
  RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

/*
* Function pointers.
*/

typedef NTSTATUS(*ZWQUERYSYSTEMINFORMATION)(
  SYSTEM_INFORMATION_CLASS SystemInformationClass,
  PVOID SystemInformation,
  ULONG SystemInformationLength,
  ULONG* ReturnLength);

typedef NTSTATUS(*PSGETCONTEXTTHREAD)(
  PETHREAD Thread,
  PCONTEXT ThreadContext,
  KPROCESSOR_MODE Mode);

typedef NTSTATUS(*PSSETCONTEXTTHREAD)(
  PETHREAD Thread,
  PCONTEXT ThreadContext,
  KPROCESSOR_MODE Mode);

typedef PPEB(*PSGETPROCESSPEB)(
  PEPROCESS Process);

/*
* Kernel functions.
*/

NTSTATUS ZwQuerySystemInformation(
  SYSTEM_INFORMATION_CLASS SystemInformationClass,
  PVOID SystemInformation,
  ULONG SystemInformationLength,
  ULONG* ReturnLength);

NTSTATUS PsGetContextThread(
  PETHREAD Thread,
  PCONTEXT ThreadContext,
  KPROCESSOR_MODE Mode);

NTSTATUS PsSetContextThread(
  PETHREAD Thread,
  PCONTEXT ThreadContext,
  KPROCESSOR_MODE Mode);

PPEB PsGetProcessPeb(
  PEPROCESS process);

#endif
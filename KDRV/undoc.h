#ifndef _UNDOC_H
#define _UNDOC_H

#include "global.h"

template<typename FUNCTION>
FUNCTION GetSystemRoutine(PCWCHAR procName)
{
  static FUNCTION functionPointer = NULL;
  if (!functionPointer)
  {
    UNICODE_STRING functionName;
    RtlInitUnicodeString(&functionName, procName);
    functionPointer = (FUNCTION)MmGetSystemRoutineAddress(&functionName);
    if (!functionPointer)
    {
      LOG_ERROR("MmGetSystemRoutineAddress\n");
      return NULL;
    }
  }
  return functionPointer;
}

/////////////////////////////////////////////////
/// NTOSKRNL
/////////////////////////////////////////////////

PVOID RtlFindExportedRoutineByName(
  PVOID ImageBase,
  PSTR RoutineName);

typedef PVOID(*RTLFINDEXPORTEDROUTINEBYNAME)(
  PVOID ImageBase,
  PSTR RoutineName);

/////////////////////////////////////////////////
/// NTDLL
/////////////////////////////////////////////////

typedef enum _SYSTEM_INFORMATION_CLASS
{
  SystemBasicInformation = 0,
  SystemPerformanceInformation = 2,
  SystemTimeOfDayInformation = 3,
  SystemProcessInformation = 5,
  SystemModuleInformation = 11,
  SystemProcessorPerformanceInformation = 8,
  SystemInterruptInformation = 23,
  SystemExceptionInformation = 33,
  SystemRegistryQuotaInformation = 37,
  SystemLookasideInformation = 45,
  SystemCodeIntegrityInformation = 103,
  SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;

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
  RTL_PROCESS_MODULE_INFORMATION Modules[ANYSIZE_ARRAY];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

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

NTSTATUS ZwQuerySystemInformation(
  SYSTEM_INFORMATION_CLASS SystemInformationClass,
  PVOID SystemInformation,
  ULONG SystemInformationLength,
  PULONG ReturnLength);

typedef NTSTATUS(*ZWQUERYSYSTEMINFORMATION)(
  SYSTEM_INFORMATION_CLASS SystemInformationClass,
  PVOID SystemInformation,
  ULONG SystemInformationLength,
  PULONG ReturnLength);

/////////////////////////////////////////////////
/// Kernel Modules
/////////////////////////////////////////////////

typedef struct _RTL_MODULE_BASIC_INFO
{
  PVOID ImageBase;
} RTL_MODULE_BASIC_INFO, * PRTL_MODULE_BASIC_INFO;
typedef struct _RTL_MODULE_EXTENDED_INFO
{
  RTL_MODULE_BASIC_INFO BasicInfo;
  ULONG ImageSize;
  USHORT FileNameOffset;
  CHAR FullPathName[0x0100];
} RTL_MODULE_EXTENDED_INFO, * PRTL_MODULE_EXTENDED_INFO;

NTSTATUS RtlQueryModuleInformation(
  ULONG* InformationLength,
  ULONG SizePerModule,
  PVOID InformationBuffer);

typedef NTSTATUS(*RTLQUERYMODULEINFORMATION)(
  ULONG* InformationLength,
  ULONG SizePerModule,
  PVOID InformationBuffer);

/////////////////////////////////////////////////
/// User Modules
/////////////////////////////////////////////////

#define PE_ERROR_VALUE (ULONG)-1

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
typedef struct _PEB64 {
  CHAR Reserved[0x10];
  PVOID ImageBaseAddress;
  PPEB_LDR_DATA Ldr;
} PEB64, * PPEB64;
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

PPEB PsGetProcessPeb(PEPROCESS Process);
PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);

typedef PVOID(*PSGETPROCESSSECTIONBASEADDRESS)(
  PEPROCESS Process);
typedef PPEB(*PSGETPROCESSPEB)(
  PEPROCESS Process);

/////////////////////////////////////////////////
/// Threading
/////////////////////////////////////////////////

#define PROCESS_SUSPEND_RESUME 0x0800

typedef struct _DESCRIPTOR
{
  WORD Pad;
  WORD Limit;
  ULONG Base;
} DESCRIPTOR, * PDESCRIPTOR;
typedef struct _FX_SAVE_AREA
{
  BYTE U[520];
  ULONG NpxSavedCpu;
  ULONG Cr0NpxState;
} FX_SAVE_AREA, * PFX_SAVE_AREA;
typedef struct _KDPC_DATA
{
  LIST_ENTRY DpcListHead;
  ULONG DpcLock;
  LONG DpcQueueDepth;
  ULONG DpcCount;
} KDPC_DATA, * PKDPC_DATA;
typedef struct _CACHED_KSTACK_LIST
{
  SLIST_HEADER SListHead;
  LONG MinimumFree;
  ULONG Misses;
  ULONG MissesLast;
} CACHED_KSTACK_LIST, * PCACHED_KSTACK_LIST;
typedef struct _PP_LOOKASIDE_LIST
{
  PGENERAL_LOOKASIDE P;
  PGENERAL_LOOKASIDE L;
} PP_LOOKASIDE_LIST, * PPP_LOOKASIDE_LIST;
typedef struct _KSPECIAL_REGISTERS
{
  ULONG Cr0;
  ULONG Cr2;
  ULONG Cr3;
  ULONG Cr4;
  ULONG KernelDr0;
  ULONG KernelDr1;
  ULONG KernelDr2;
  ULONG KernelDr3;
  ULONG KernelDr6;
  ULONG KernelDr7;
  DESCRIPTOR Gdtr;
  DESCRIPTOR Idtr;
  WORD Tr;
  WORD Ldtr;
  ULONG Reserved[6];
} KSPECIAL_REGISTERS, * PKSPECIAL_REGISTERS;
typedef struct _PPM_IDLE_STATE
{
  LONG* IdleHandler;
  ULONG Context;
  ULONG Latency;
  ULONG Power;
  ULONG TimeCheck;
  ULONG StateFlags;
  UCHAR PromotePercent;
  UCHAR DemotePercent;
  UCHAR PromotePercentBase;
  UCHAR DemotePercentBase;
  UCHAR StateType;
} PPM_IDLE_STATE, * PPPM_IDLE_STATE;
typedef struct _PPM_IDLE_STATES
{
  ULONG Type;
  ULONG Count;
  ULONG Flags;
  ULONG TargetState;
  ULONG ActualState;
  ULONG OldState;
  ULONG TargetProcessors;
  PPM_IDLE_STATE State[1];
} PPM_IDLE_STATES, * PPPM_IDLE_STATES;
typedef struct _PROCESSOR_IDLE_TIMES
{
  UINT64 StartTime;
  UINT64 EndTime;
  ULONG Reserved[4];
} PROCESSOR_IDLE_TIMES, * PPROCESSOR_IDLE_TIMES;
typedef struct _KPROCESSOR_STATE
{
  CONTEXT ContextFrame;
  KSPECIAL_REGISTERS SpecialRegisters;
} KPROCESSOR_STATE, * PKPROCESSOR_STATE;
typedef struct _PPM_IDLE_STATE_ACCOUNTING
{
  ULONG IdleTransitions;
  ULONG FailedTransitions;
  ULONG InvalidBucketIndex;
  UINT64 TotalTime;
  ULONG IdleTimeBuckets[6];
} PPM_IDLE_STATE_ACCOUNTING, * PPPM_IDLE_STATE_ACCOUNTING;
typedef struct _PPM_IDLE_ACCOUNTING
{
  ULONG StateCount;
  ULONG TotalTransitions;
  ULONG ResetCount;
  UINT64 StartTime;
  PPM_IDLE_STATE_ACCOUNTING State[1];
} PPM_IDLE_ACCOUNTING, * PPPM_IDLE_ACCOUNTING;
typedef struct _PPM_PERF_STATE
{
  ULONG Frequency;
  ULONG Power;
  UCHAR PercentFrequency;
  UCHAR IncreaseLevel;
  UCHAR DecreaseLevel;
  UCHAR Type;
  UINT64 Control;
  UINT64 Status;
  ULONG TotalHitCount;
  ULONG DesiredCount;
} PPM_PERF_STATE, * PPPM_PERF_STATE;
typedef struct _PPM_PERF_STATES
{
  ULONG Count;
  ULONG MaxFrequency;
  ULONG MaxPerfState;
  ULONG MinPerfState;
  ULONG LowestPState;
  ULONG IncreaseTime;
  ULONG DecreaseTime;
  UCHAR BusyAdjThreshold;
  UCHAR Reserved;
  UCHAR ThrottleStatesOnly;
  UCHAR PolicyType;
  ULONG TimerInterval;
  ULONG Flags;
  ULONG TargetProcessors;
  LONG* PStateHandler;
  ULONG PStateContext;
  LONG* TStateHandler;
  ULONG TStateContext;
  ULONG* FeedbackHandler;
  PPM_PERF_STATE State[1];
} PPM_PERF_STATES, * PPPM_PERF_STATES;
typedef struct _PROCESSOR_POWER_STATE
{
  PVOID IdleFunction;
  PPPM_IDLE_STATES IdleStates;
  UINT64 LastTimeCheck;
  UINT64 LastIdleTime;
  PROCESSOR_IDLE_TIMES IdleTimes;
  PPPM_IDLE_ACCOUNTING IdleAccounting;
  PPPM_PERF_STATES PerfStates;
  ULONG LastKernelUserTime;
  ULONG LastIdleThreadKTime;
  UINT64 LastGlobalTimeHv;
  UINT64 LastProcessorTimeHv;
  UCHAR ThermalConstraint;
  UCHAR LastBusyPercentage;
  BYTE Flags[6];
  KTIMER PerfTimer;
  KDPC PerfDpc;
  ULONG LastSysTime;
  PVOID PStateMaster;
  ULONG PStateSet;
  ULONG CurrentPState;
  ULONG Reserved0;
  ULONG DesiredPState;
  ULONG Reserved1;
  ULONG PStateIdleStartTime;
  ULONG PStateIdleTime;
  ULONG LastPStateIdleTime;
  ULONG PStateStartTime;
  ULONG WmiDispatchPtr;
  LONG WmiInterfaceEnabled;
} PROCESSOR_POWER_STATE, * PPROCESSOR_POWER_STATE;
typedef struct _KNODE
{
  SLIST_HEADER PagedPoolSListHead;
  SLIST_HEADER NonPagedPoolSListHead[3];
  SLIST_HEADER PfnDereferenceSListHead;
  ULONG ProcessorMask;
  UCHAR Color;
  UCHAR Seed;
  UCHAR NodeNumber;
  ULONG Flags;
  ULONG MmShiftedColor;
  ULONG FreeCount[2];
  PSINGLE_LIST_ENTRY PfnDeferredList;
  CACHED_KSTACK_LIST CachedKernelStacks;
} KNODE, * PKNODE;
typedef struct _PS_CLIENT_SECURITY_CONTEXT
{
  union
  {
    ULONG ImpersonationData;
    PVOID ImpersonationToken;
    ULONG ImpersonationLevel : 2;
    ULONG EffectiveOnly : 1;
  };
} PS_CLIENT_SECURITY_CONTEXT, * PPS_CLIENT_SECURITY_CONTEXT;
typedef struct _PSP_RATE_APC
{
  union
  {
    SINGLE_LIST_ENTRY NextApc;
    ULONGLONG ExcessCycles;
  };
  ULONGLONG TargetGEneration;
  KAPC RateApc;
} PSP_RATE_APC, * PPSP_RATE_APC;
typedef struct _TERMINATION_PORT
{
  PVOID Next;
  PVOID Port;
} TERMINATION_PORT, * PTERMINATION_PORT;
typedef struct _KPRCB
{
  WORD MinorVersion;
  WORD MajorVersion;
  PKTHREAD CurrentThread;
  PKTHREAD NextThread;
  PKTHREAD IdleThread;
  UCHAR Number;
  UCHAR NestingLevel;
  WORD BuildType;
  ULONG SetMember;
  CHAR CpuType;
  CHAR CpuID;
  union
  {
    WORD CpuStep;
    struct _Dummy0
    {
      UCHAR CpuStepping;
      UCHAR CpuModel;
    };
  };
  KPROCESSOR_STATE ProcessorState;
  ULONG KernelReserved[16];
  ULONG HalReserved[16];
  ULONG CFlushSize;
  UCHAR PrcbPad0[88];
  KSPIN_LOCK_QUEUE LockQueue[33];
  PKTHREAD NpxThread;
  ULONG InterruptCount;
  ULONG KernelTime;
  ULONG UserTime;
  ULONG DpcTime;
  ULONG DpcTimeCount;
  ULONG InterruptTime;
  ULONG AdjustDpcThreshold;
  ULONG PageColor;
  UCHAR SkipTick;
  UCHAR DebuggerSavedIRQL;
  UCHAR NodeColor;
  UCHAR PollSlot;
  ULONG NodeShiftedColor;
  PKNODE ParentNode;
  ULONG MultiThreadProcessorSet;
  PVOID MultiThreadSetMaster;
  ULONG SecondaryColorMask;
  ULONG DpcTimeLimit;
  ULONG CcFastReadNoWait;
  ULONG CcFastReadWait;
  ULONG CcFastReadNotPossible;
  ULONG CcCopyReadNoWait;
  ULONG CcCopyReadWait;
  ULONG CcCopyReadNoWaitMiss;
  LONG MmSpinLockOrdering;
  LONG IoReadOperationCount;
  LONG IoWriteOperationCount;
  LONG IoOtherOperationCount;
  LARGE_INTEGER IoReadTransferCount;
  LARGE_INTEGER IoWriteTransferCount;
  LARGE_INTEGER IoOtherTransferCount;
  ULONG CcFastMdlReadNoWait;
  ULONG CcFastMdlReadWait;
  ULONG CcFastMdlReadNotPossible;
  ULONG CcMapDataNoWait;
  ULONG CcMapDataWait;
  ULONG CcPinMappedDataCount;
  ULONG CcPinReadNoWait;
  ULONG CcPinReadWait;
  ULONG CcMdlReadNoWait;
  ULONG CcMdlReadWait;
  ULONG CcLazyWriteHotSpots;
  ULONG CcLazyWriteIos;
  ULONG CcLazyWritePages;
  ULONG CcDataFlushes;
  ULONG CcDataPages;
  ULONG CcLostDelayedWrites;
  ULONG CcFastReadResourceMiss;
  ULONG CcCopyReadWaitMiss;
  ULONG CcFastMdlReadResourceMiss;
  ULONG CcMapDataNoWaitMiss;
  ULONG CcMapDataWaitMiss;
  ULONG CcPinReadNoWaitMiss;
  ULONG CcPinReadWaitMiss;
  ULONG CcMdlReadNoWaitMiss;
  ULONG CcMdlReadWaitMiss;
  ULONG CcReadAheadIos;
  ULONG KeAlignmentFixupCount;
  ULONG KeExceptionDispatchCount;
  ULONG KeSystemCalls;
  ULONG PrcbPad1[3];
  PP_LOOKASIDE_LIST PPLookasideList[16];
  GENERAL_LOOKASIDE_POOL PPNPagedLookasideList[32];
  GENERAL_LOOKASIDE_POOL PPPagedLookasideList[32];
  ULONG PacketBarrier;
  LONG ReverseStall;
  PVOID IpiFrame;
  UCHAR PrcbPad2[52];
  VOID* CurrentPacket[3];
  ULONG TargetSet;
  PVOID WorkerRoutine;
  ULONG IpiFrozen;
  UCHAR PrcbPad3[40];
  ULONG RequestSummary;
  PVOID SignalDone;
  UCHAR PrcbPad4[56];
  KDPC_DATA DpcData[2];
  PVOID DpcStack;
  LONG MaximumDpcQueueDepth;
  ULONG DpcRequestRate;
  ULONG MinimumDpcRate;
  UCHAR DpcInterruptRequested;
  UCHAR DpcThreadRequested;
  UCHAR DpcRoutineActive;
  UCHAR DpcThreadActive;
  ULONG PrcbLock;
  ULONG DpcLastCount;
  ULONG TimerHand;
  ULONG TimerRequest;
  PVOID PrcbPad41;
  KEVENT DpcEvent;
  UCHAR ThreadDpcEnable;
  UCHAR QuantumEnd;
  UCHAR PrcbPad50;
  UCHAR IdleSchedule;
  LONG DpcSetEventRequest;
  LONG Sleeping;
  ULONG PeriodicCount;
  ULONG PeriodicBias;
  UCHAR PrcbPad5[6];
  LONG TickOffset;
  KDPC CallDpc;
  LONG ClockKeepAlive;
  UCHAR ClockCheckSlot;
  UCHAR ClockPollCycle;
  UCHAR PrcbPad6[2];
  LONG DpcWatchdogPeriod;
  LONG DpcWatchdogCount;
  LONG ThreadWatchdogPeriod;
  LONG ThreadWatchdogCount;
  ULONG PrcbPad70[2];
  LIST_ENTRY WaitListHead;
  ULONG WaitLock;
  ULONG ReadySummary;
  ULONG QueueIndex;
  SINGLE_LIST_ENTRY DeferredReadyListHead;
  UINT64 StartCycles;
  UINT64 CycleTime;
  UINT64 PrcbPad71[3];
  LIST_ENTRY DispatcherReadyListHead[32];
  PVOID ChainedInterruptList;
  LONG LookasideIrpFloat;
  LONG MmPageFaultCount;
  LONG MmCopyOnWriteCount;
  LONG MmTransitionCount;
  LONG MmCacheTransitionCount;
  LONG MmDemandZeroCount;
  LONG MmPageReadCount;
  LONG MmPageReadIoCount;
  LONG MmCacheReadCount;
  LONG MmCacheIoCount;
  LONG MmDirtyPagesWriteCount;
  LONG MmDirtyWriteIoCount;
  LONG MmMappedPagesWriteCount;
  LONG MmMappedWriteIoCount;
  ULONG CachedCommit;
  ULONG CachedResidentAvailable;
  PVOID HyperPte;
  UCHAR CpuVendor;
  UCHAR PrcbPad9[3];
  UCHAR VendorString[13];
  UCHAR InitialApicId;
  UCHAR CoresPerPhysicalProcessor;
  UCHAR LogicalProcessorsPerPhysicalProcessor;
  ULONG MHz;
  ULONG FeatureBits;
  LARGE_INTEGER UpdateSignature;
  UINT64 IsrTime;
  UINT64 SpareField1;
  FX_SAVE_AREA NpxSaveArea;
  PROCESSOR_POWER_STATE PowerState;
  KDPC DpcWatchdogDpc;
  KTIMER DpcWatchdogTimer;
  PVOID WheaInfo;
  PVOID EtwSupport;
  SLIST_HEADER InterruptObjectPool;
  LARGE_INTEGER HypercallPagePhysical;
  PVOID HypercallPageVirtual;
  PVOID RateControl;
  CACHE_DESCRIPTOR Cache[5];
  ULONG CacheCount;
  ULONG CacheProcessorMask[5];
  UCHAR LogicalProcessorsPerCore;
  UCHAR PrcbPad8[3];
  ULONG PackageProcessorSet;
  ULONG CoreProcessorSet;
} KPRCB, * PKPRCB;
typedef struct _KTHREAD
{
  DISPATCHER_HEADER Header;
  UINT64 CycleTime;
  ULONG HighCycleTime;
  UINT64 QuantumTarget;
  PVOID InitialStack;
  PVOID StackLimit;
  PVOID KernelStack;
  ULONG ThreadLock;
  union
  {
    KAPC_STATE ApcState;
    UCHAR ApcStateFill[23];
  };
  CHAR Priority;
  WORD NextProcessor;
  WORD DeferredProcessor;
  ULONG ApcQueueLock;
  ULONG ContextSwitches;
  UCHAR State;
  UCHAR NpxState;
  UCHAR WaitIrql;
  CHAR WaitMode;
  LONG WaitStatus;
  union
  {
    PKWAIT_BLOCK WaitBlockList;
    PKGATE GateObject;
  };
  union
  {
    ULONG KernelStackResident : 1;
    ULONG ReadyTransition : 1;
    ULONG ProcessReadyQueue : 1;
    ULONG WaitNext : 1;
    ULONG SystemAffinityActive : 1;
    ULONG Alertable : 1;
    ULONG GdiFlushActive : 1;
    ULONG Reserved : 25;
    LONG MiscFlags;
  };
  UCHAR WaitReason;
  UCHAR SwapBusy;
  UCHAR Alerted[2];
  union
  {
    LIST_ENTRY WaitListEntry;
    SINGLE_LIST_ENTRY SwapListEntry;
  };
  PKQUEUE Queue;
  ULONG WaitTime;
  union
  {
    struct _Dummy0
    {
      SHORT KernelApcDisable;
      SHORT SpecialApcDisable;
    };
    ULONG CombinedApcDisable;
  };
  PVOID Teb;
  union
  {
    KTIMER Timer;
    UCHAR TimerFill[40];
  };
  union
  {
    ULONG AutoAlignment : 1;
    ULONG DisableBoost : 1;
    ULONG EtwStackTraceApc1Inserted : 1;
    ULONG EtwStackTraceApc2Inserted : 1;
    ULONG CycleChargePending : 1;
    ULONG CalloutActive : 1;
    ULONG ApcQueueable : 1;
    ULONG EnableStackSwap : 1;
    ULONG GuiThread : 1;
    ULONG ReservedFlags : 23;
    LONG ThreadFlags;
  };
  union
  {
    KWAIT_BLOCK WaitBlock[4];
    struct _Dummy0
    {
      UCHAR WaitBlockFill0[23];
      UCHAR IdealProcessor;
    };
    struct _Dummy1
    {
      UCHAR WaitBlockFill1[47];
      CHAR PreviousMode;
    };
    struct _Dummy2
    {
      UCHAR WaitBlockFill2[71];
      UCHAR ResourceIndex;
    };
    UCHAR WaitBlockFill3[95];
  };
  UCHAR LargeStack;
  LIST_ENTRY QueueListEntry;
  PKTRAP_FRAME TrapFrame;
  PVOID FirstArgument;
  union
  {
    PVOID CallbackStack;
    ULONG CallbackDepth;
  };
  PVOID ServiceTable;
  UCHAR ApcStateIndex;
  CHAR BasePriority;
  CHAR PriorityDecrement;
  UCHAR Preempted;
  UCHAR AdjustReason;
  CHAR AdjustIncrement;
  UCHAR Spare01;
  CHAR Saturation;
  ULONG SystemCallNumber;
  ULONG Spare02;
  ULONG UserAffinity;
  PKPROCESS Process;
  ULONG Affinity;
  PKAPC_STATE ApcStatePointer[2];
  union
  {
    KAPC_STATE SavedApcState;
    UCHAR SavedApcStateFill[23];
  };
  CHAR FreezeCount;
  CHAR SuspendCount;
  UCHAR UserIdealProcessor;
  UCHAR Spare03;
  UCHAR Iopl;
  PVOID Win32Thread;
  PVOID StackBase;
  union
  {
    KAPC SuspendApc;
    struct _Dummy0
    {
      UCHAR SuspendApcFill0[1];
      CHAR Spare04;
    };
    struct _Dummy1
    {
      UCHAR SuspendApcFill1[3];
      UCHAR QuantumReset;
    };
    struct _Dummy2
    {
      UCHAR SuspendApcFill2[4];
      ULONG KernelTime;
    };
    struct _Dummy3
    {
      UCHAR SuspendApcFill3[36];
      PKPRCB WaitPrcb;
    };
    struct _Dummy4
    {
      UCHAR SuspendApcFill4[40];
      PVOID LegoData;
    };
    UCHAR SuspendApcFill5[47];
  };
  UCHAR PowerState;
  ULONG UserTime;
  union
  {
    KSEMAPHORE SuspendSemaphore;
    UCHAR SuspendSemaphorefill[20];
  };
  ULONG SListFaultCount;
  LIST_ENTRY ThreadListEntry;
  LIST_ENTRY MutantListHead;
  PVOID SListFaultAddress;
  PVOID MdlForLockedTeb;
} KTHREAD, * PKTHREAD;

typedef struct _ETHREAD
{
  KTHREAD Tcb;
  LARGE_INTEGER CreateTime;
  union
  {
    LARGE_INTEGER ExitTime;
    LIST_ENTRY KeyedWaitChain;
  };
  union
  {
    LONG ExitStatus;
    PVOID OfsChain;
  };
  union
  {
    LIST_ENTRY PostBlockList;
    struct _Dummy0
    {
      PVOID ForwardLinkShadow;
      PVOID StartAddress;
    } Shadow;
  };
  union
  {
    PTERMINATION_PORT TerminationPort;
    PETHREAD ReaperLink;
    PVOID KeyedWaitValue;
    PVOID Win32StartParameter;
  };
  ULONG ActiveTimerListLock;
  LIST_ENTRY ActiveTimerListHead;
  CLIENT_ID Cid;
  union
  {
    KSEMAPHORE KeyedWaitSemaphore;
    KSEMAPHORE AlpcWaitSemaphore;
  };
  PS_CLIENT_SECURITY_CONTEXT ClientSecurity;
  LIST_ENTRY IrpList;
  ULONG TopLevelIrp;
  PDEVICE_OBJECT DeviceToVerify;
  PSP_RATE_APC* RateControlApc;
  PVOID Win32StartAddress;
  PVOID SparePtr0;
  LIST_ENTRY ThreadListEntry;
  EX_RUNDOWN_REF RundownProtect;
  EX_PUSH_LOCK ThreadLock;
  ULONG ReadClusterSize;
  LONG MmLockOrdering;
  ULONG CrossThreadFlags;
  ULONG Terminated : 1;
  ULONG ThreadInserted : 1;
  ULONG HideFromDebugger : 1;
  ULONG ActiveImpersonationInfo : 1;
  ULONG SystemThread : 1;
  ULONG HardErrorsAreDisabled : 1;
  ULONG BreakOnTermination : 1;
  ULONG SkipCreationMsg : 1;
  ULONG SkipTerminationMsg : 1;
  ULONG CopyTokenOnOpen : 1;
  ULONG ThreadIoPriority : 3;
  ULONG ThreadPagePriority : 3;
  ULONG RundownFail : 1;
  ULONG SameThreadPassiveFlags;
  ULONG ActiveExWorker : 1;
  ULONG ExWorkerCanWaitUser : 1;
  ULONG MemoryMaker : 1;
  ULONG ClonedThread : 1;
  ULONG KeyedEventInUse : 1;
  ULONG RateApcState : 2;
  ULONG SelfTerminate : 1;
  ULONG SameThreadApcFlags;
  ULONG Spare : 1;
  ULONG StartAddressInvalid : 1;
  ULONG EtwPageFaultCalloutActive : 1;
  ULONG OwnsProcessWorkingSetExclusive : 1;
  ULONG OwnsProcessWorkingSetShared : 1;
  ULONG OwnsSystemWorkingSetExclusive : 1;
  ULONG OwnsSystemWorkingSetShared : 1;
  ULONG OwnsSessionWorkingSetExclusive : 1;
  ULONG OwnsSessionWorkingSetShared : 1;
  ULONG OwnsProcessAddressSpaceExclusive : 1;
  ULONG OwnsProcessAddressSpaceShared : 1;
  ULONG SuppressSymbolLoad : 1;
  ULONG Prefetching : 1;
  ULONG OwnsDynamicMemoryShared : 1;
  ULONG OwnsChangeControlAreaExclusive : 1;
  ULONG OwnsChangeControlAreaShared : 1;
  ULONG PriorityRegionActive : 4;
  UCHAR CacheManagerActive;
  UCHAR DisablePageFaultClustering;
  UCHAR ActiveFaultCount;
  ULONG AlpcMessageId;
  union
  {
    PVOID AlpcMessage;
    ULONG AlpcReceiveAttributeSet;
  };
  LIST_ENTRY AlpcWaitListEntry;
  ULONG CacheManagerCount;
} ETHREAD;

NTSTATUS PsSuspendProcess(PEPROCESS Process);
NTSTATUS PsResumeProcess(PEPROCESS Process);
NTSTATUS PsGetContextThread(
  PETHREAD Thread,
  PCONTEXT ThreadContext,
  KPROCESSOR_MODE Mode);

typedef NTSTATUS(*PSSUSPENDPROCESS)(
  PEPROCESS Process);
typedef NTSTATUS(*PSRESUMEPROCESS)(
  PEPROCESS Process);
typedef NTSTATUS(*PSGETCONTEXTTHREAD)(
  PETHREAD Thread,
  PCONTEXT ThreadContext,
  KPROCESSOR_MODE Mode);

#endif
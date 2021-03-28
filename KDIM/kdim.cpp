#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <windef.h>

#include "ntwow64.h"

#define LOG(MSG, ...)                     \
DbgPrintEx(0, 0, "[+] " MSG, __VA_ARGS__)

#define SLEEP(MS)                                 \
LARGE_INTEGER delay;                              \
delay.QuadPart = -1 * (10000 * MS);               \
KeDelayExecutionThread(KernelMode, FALSE, &delay)

template<typename FUNCTION>
FUNCTION GetSystemAddress(PCWCHAR procName)
{
  static FUNCTION functionPointer = NULL;
  if (!functionPointer)
  {
    UNICODE_STRING functionName;
    RtlInitUnicodeString(&functionName, procName);
    functionPointer = (FUNCTION)MmGetSystemRoutineAddress(&functionName);
  }
  return functionPointer;
}

typedef enum _SYSTEM_INFORMATION_CLASS
{
  SystemBasicInformation = 0,
  SystemPerformanceInformation = 2,
  SystemTimeOfDayInformation = 3,
  SystemProcessInformation = 5,
  SystemProcessorPerformanceInformation = 8,
  SystemInterruptInformation = 23,
  SystemExceptionInformation = 33,
  SystemRegistryQuotaInformation = 37,
  SystemLookasideInformation = 45,
  SystemCodeIntegrityInformation = 103,
  SystemPolicyInformation = 134,
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
typedef struct _SECURITY_ATTRIBUTES
{
  DWORD  nLength;
  LPVOID lpSecurityDescriptor;
  BOOL   bInheritHandle;
} SECURITY_ATTRIBUTES, * PSECURITY_ATTRIBUTES, * LPSECURITY_ATTRIBUTES;

typedef DWORD(*LPTHREAD_START_ROUTINE)(
  LPVOID lpThreadParameter);
typedef HMODULE(*LOADLIBRARYA)(
  LPCSTR lpLibFileName);
typedef HANDLE(*CREATETHREAD)(
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  SIZE_T dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID lpParameter,
  DWORD dwCreationFlags,
  LPDWORD lpThreadId);

typedef NTSTATUS(*ZWQUERYSYSTEMINFORMATION)(
  SYSTEM_INFORMATION_CLASS SystemInformationClass,
  PVOID SystemInformation,
  ULONG SystemInformationLength,
  PULONG ReturnLength);
typedef PPEB(*PSGETPROCESSPEB)(
  PEPROCESS process);
typedef NTSTATUS(*NTSUSPENDTHREAD)(
  HANDLE ThreadHandle,
  PULONG PreviousSuspendCount);
typedef HANDLE(*CREATEREMOTETHREAD)(
  HANDLE hProcess,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  SIZE_T dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID lpParameter,
  DWORD dwCreationFlags,
  LPDWORD lpThreadId);

NTSTATUS ZwQuerySystemInformation(
  SYSTEM_INFORMATION_CLASS SystemInformationClass,
  PVOID SystemInformation,
  ULONG SystemInformationLength,
  PULONG ReturnLength)
{
  return GetSystemAddress<ZWQUERYSYSTEMINFORMATION>(L"ZwQuerySystemInformation")(
    SystemInformationClass,
    SystemInformation,
    SystemInformationLength,
    ReturnLength);
}
PPEB PsGetProcessPeb(
  PEPROCESS Process)
{
  return GetSystemAddress<PSGETPROCESSPEB>(L"PsGetProcessPeb")(
    Process);
}

template<typename TYPE>
TYPE* RtlAllocateMemory(BOOLEAN zeroMemory, SIZE_T numElements)
{
  TYPE* ptr = (TYPE*)ExAllocatePoolWithTag(NonPagedPool, sizeof(TYPE) * numElements, 0);
  if (zeroMemory && ptr)
    RtlZeroMemory(ptr, sizeof(TYPE) * numElements);
  return ptr;
}
VOID RtlFreeMemory(PVOID ptr)
{
  ExFreePool(ptr);
}

PVOID SanitizeUserPointer(PVOID base, SIZE_T size)
{
  MEMORY_BASIC_INFORMATION memInfo;
  ZwQueryVirtualMemory(ZwCurrentProcess(), base, MemoryBasicInformation, &memInfo, sizeof(MEMORY_BASIC_INFORMATION), NULL);
  if (!(((ULONG_PTR)memInfo.BaseAddress + memInfo.RegionSize) < (((ULONG_PTR)base + size))))
    if (memInfo.State & MEM_COMMIT || !(memInfo.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
      if (memInfo.Protect & PAGE_EXECUTE_READWRITE || memInfo.Protect & PAGE_EXECUTE_WRITECOPY || memInfo.Protect & PAGE_READWRITE || memInfo.Protect & PAGE_WRITECOPY)
        return base;
  return NULL;
}

PLDR_DATA_TABLE_ENTRY32 GetDataTableEntry32(PPEB64 peb)
{
  if (SanitizeUserPointer(peb, sizeof(PEB64)))
    if (peb->Ldr)
      if (SanitizeUserPointer(peb->Ldr, sizeof(PEB_LDR_DATA64)))
        if (peb->Ldr->Initialized)
          return CONTAINING_RECORD(peb->Ldr->InLoadOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
  return NULL;
}
PLDR_DATA_TABLE_ENTRY64 GetDataTableEntry64(PPEB64 peb)
{
  if (SanitizeUserPointer(peb, sizeof(PEB64)))
    if (peb->Ldr)
      if (SanitizeUserPointer(peb->Ldr, sizeof(PEB_LDR_DATA64)))
        if (peb->Ldr->Initialized)
          return CONTAINING_RECORD(peb->Ldr->InLoadOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY64, InLoadOrderLinks);
  return NULL;
}

HANDLE GetProcessId(PWCHAR imageName)
{
  HANDLE pid = NULL;
  UNICODE_STRING imageNameString;
  RtlInitUnicodeString(&imageNameString, imageName);
  PSYSTEM_PROCESS_INFORMATION images = RtlAllocateMemory<SYSTEM_PROCESS_INFORMATION>(TRUE, 1024 * 1024);
  ZwQuerySystemInformation(SystemProcessInformation, images, sizeof(SYSTEM_PROCESS_INFORMATION) * 1024 * 1024, NULL);
  for (ULONG i = 0; i < 1024 * 1024; ++i)
  {
    if (&images[i].ImageName.Buffer != 0)
    {
      LOG("%wZ\n", &images[i].ImageName);
      if (RtlCompareUnicodeString(&imageNameString, &images[i].ImageName, TRUE) == 0)
      {
        pid = images[i].UniqueProcessId;
        break;
      }
    }
  }
  RtlFreeMemory(images);
  return pid;
}

PVOID GetModuleBase32(HANDLE pid, PCHAR moduleName)
{
  PVOID baseAddr = NULL;
  PEPROCESS process = NULL;
  ANSI_STRING moduleNameString;
  RtlInitAnsiString(&moduleNameString, moduleName);
  PsLookupProcessByProcessId(pid, &process);
  KAPC_STATE apc;
  KeStackAttachProcess(process, &apc);
  PPEB64 peb64 = (PPEB64)PsGetProcessPeb(process);
  PLDR_DATA_TABLE_ENTRY32 modules = GetDataTableEntry32(peb64);
  PLDR_DATA_TABLE_ENTRY32 module = NULL;
  PLIST_ENTRY moduleList = (PLIST_ENTRY)modules->InLoadOrderLinks.Flink;
  PLIST_ENTRY moduleEntry = moduleList->Flink;
  while (moduleEntry != moduleList)
  {
    module = CONTAINING_RECORD(moduleEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
    if (&module->BaseDllName.Buffer != 0)
    {
      LOG("%s\n", (PCHAR)&module->BaseDllName.Buffer);
      //if (RtlCompareString(&moduleNameString, &module->BaseDllName, TRUE) == 0)
      //{
      //  baseAddr = (PVOID)module->DllBase;
      //  break;
      //}
    }
    moduleEntry = moduleEntry->Flink;
  }
  KeUnstackDetachProcess(&apc);
  return baseAddr;
}
PVOID GetModuleBase64(HANDLE pid, PWCHAR moduleName)
{
  PVOID baseAddr = NULL;
  PEPROCESS process = NULL;
  UNICODE_STRING moduleNameString;
  RtlInitUnicodeString(&moduleNameString, moduleName);
  PsLookupProcessByProcessId(pid, &process);
  KAPC_STATE apc;
  KeStackAttachProcess(process, &apc);
  PPEB64 peb64 = (PPEB64)PsGetProcessPeb(process);
  PLDR_DATA_TABLE_ENTRY64 modules = GetDataTableEntry64(peb64);
  PLDR_DATA_TABLE_ENTRY64 module = NULL;
  PLIST_ENTRY moduleList = (PLIST_ENTRY)modules->InLoadOrderLinks.Flink;
  PLIST_ENTRY moduleEntry = moduleList->Flink;
  while (moduleEntry != moduleList)
  {
    module = CONTAINING_RECORD(moduleEntry, LDR_DATA_TABLE_ENTRY64, InLoadOrderLinks);
    if (&module->BaseDllName.Buffer != 0)
    {
      if (RtlCompareUnicodeString(&moduleNameString, &module->BaseDllName, TRUE) == 0)
      {
        LOG("found %wZ\n", &module->BaseDllName);
        baseAddr = (PVOID)module->DllBase;
        break;
      }
    }
    moduleEntry = moduleEntry->Flink;
  }
  KeUnstackDetachProcess(&apc);
  return baseAddr;
}

ULONG DllThread(HINSTANCE instance)
{
  while (1)
  {

  }
  return 0;
}

VOID DriverUnload(PDRIVER_OBJECT driverObject)
{
  LOG("KDIM deinitialized\n");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING regPath)
{
  UNREFERENCED_PARAMETER(regPath);
  NTSTATUS status = STATUS_SUCCESS;
  driverObject->DriverUnload = DriverUnload;
  __try
  {
    HANDLE pid = (HANDLE)5964; //GetProcessId(L"explorer.exe");
    LOG("pid: %u\n", pid);
    PVOID modBase = GetModuleBase64(pid, L"explorer.exe");
    LOG("modBase: %p\n", modBase);
    PVOID ntdllBase = GetModuleBase64(pid, L"ntdll.dll");
    LOG("ntdllBase: %p\n", ntdllBase);
    PVOID kernel32Base = GetModuleBase64(pid, L"kernel32.dll");
    LOG("kernel32Base: %p\n", kernel32Base);
    NTSUSPENDTHREAD ntSuspendThread = (NTSUSPENDTHREAD)((ULONG_PTR)ntdllBase + 0xA0430);
    LOG("ntSuspendThread: %p\n", ntSuspendThread);
    CREATEREMOTETHREAD createRemoteThread = (CREATEREMOTETHREAD)((ULONG_PTR)kernel32Base + 0xfc200);
    LOG("createRemoteThread: %p\n", createRemoteThread);
    LOADLIBRARYA loadLibraryA = (LOADLIBRARYA)((LONG_PTR)kernel32Base + 0x1ebb0);
    LOG("loadLibraryA: %p\n", loadLibraryA);
    CREATETHREAD createThread = (CREATETHREAD)((ULONG_PTR)kernel32Base + 0x1a860);
    LOG("createThread: %p\n", createThread);
    PEPROCESS process = NULL;
    PsLookupProcessByProcessId(pid, &process);
    KAPC_STATE apc;
    KeStackAttachProcess(process, &apc);
    LOG("attached to process\n");
    LOG("calling create thread\n");
    createThread(NULL, 0, (LPTHREAD_START_ROUTINE)DllThread, NULL, 0, NULL);
    KeUnstackDetachProcess(&apc);
    LOG("detached from process\n");
    //SLEEP(1000);
    LOG("KDIM initialized\n");
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    LOG("something went wrong\n");
    status = STATUS_FAIL_CHECK;
  }
  return status;
}
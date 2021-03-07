#ifndef _UNDOC_H
#define _UNDOC_H

#include "global.h"

template<typename Function>
Function GetSystemAddress(PCWCHAR procName)
{
  static Function functionPointer = NULL;
  if (!functionPointer)
  {
    UNICODE_STRING functionName;
    RtlInitUnicodeString(&functionName, procName);
    functionPointer = (Function)MmGetSystemRoutineAddress(&functionName);
    if (!functionPointer)
    {
      LOG_ERROR("MmGetSystemRoutineAddress\n");
      return NULL;
    }
  }
  return functionPointer;
}

/////////////////////////////////////////////////
/////////////////////////////////////////////////
/////////////////////////////////////////////////

PVOID PsGetProcessSectionBaseAddress(
  PEPROCESS Process);

typedef PVOID(*PSGETPROCESSSECTIONBASEADDRESS)(
  PEPROCESS Process);

/////////////////////////////////////////////////
/////////////////////////////////////////////////
/////////////////////////////////////////////////

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
/////////////////////////////////////////////////
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
/////////////////////////////////////////////////
/////////////////////////////////////////////////

PVOID RtlFindExportedRoutineByName(
  PVOID ImageBase,
  PSTR RoutineName);

typedef PVOID(*RTLFINDEXPORTEDROUTINEBYNAME)(
  PVOID ImageBase,
  PSTR RoutineName);

#endif
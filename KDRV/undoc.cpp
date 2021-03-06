#include "undoc.h"

PVOID PsGetProcessSectionBaseAddress(
  PEPROCESS Process)
{
  static PSGETPROCESSSECTIONBASEADDRESS functionPointer = NULL;
  if (!functionPointer)
  {
    UNICODE_STRING functionName;
    RtlInitUnicodeString(&functionName, L"PsGetProcessSectionBaseAddress");
    functionPointer = (PSGETPROCESSSECTIONBASEADDRESS)MmGetSystemRoutineAddress(&functionName);
    if (!functionPointer)
    {
      LOG_ERROR("MmGetSystemRoutineAddress\n");
      return NULL;
    }
  }
  return functionPointer(Process);
}

NTSTATUS ZwQuerySystemInformation(
  SYSTEM_INFORMATION_CLASS SystemInformationClass,
  PVOID SystemInformation,
  ULONG SystemInformationLength,
  PULONG ReturnLength)
{
  static ZWQUERYSYSTEMINFORMATION functionPointer = NULL;
  if (!functionPointer)
  {
    UNICODE_STRING functionName;
    RtlInitUnicodeString(&functionName, L"ZwQuerySystemInformation");
    functionPointer = (ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&functionName);
    if (!functionPointer)
    {
      LOG_ERROR("MmGetSystemRoutineAddress\n");
      return STATUS_INVALID_ADDRESS;
    }
  }
  return functionPointer(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

NTSTATUS RtlQueryModuleInformation(
  ULONG* InformationLength,
  ULONG SizePerModule,
  PVOID InformationBuffer)
{
  static RTLQUERYMODULEINFORMATION functionPointer = NULL;
  if (!functionPointer)
  {
    UNICODE_STRING functionName;
    RtlInitUnicodeString(&functionName, L"RtlQueryModuleInformation");
    functionPointer = (RTLQUERYMODULEINFORMATION)MmGetSystemRoutineAddress(&functionName);
    if (!functionPointer)
    {
      LOG_ERROR("MmGetSystemRoutineAddress\n");
      return STATUS_INVALID_ADDRESS;
    }
  }
  return functionPointer(InformationLength, SizePerModule, InformationBuffer);
}

PVOID RtlFindExportedRoutineByName(
  PVOID ImageBase,
  PSTR RoutineName)
{
  static RTLFINDEXPORTEDROUTINEBYNAME functionPointer = NULL;
  if (!functionPointer)
  {
    UNICODE_STRING functionName;
    RtlInitUnicodeString(&functionName, L"RtlFindExportedRoutineByName");
    functionPointer = (RTLFINDEXPORTEDROUTINEBYNAME)MmGetSystemRoutineAddress(&functionName);
    if (!functionPointer)
    {
      LOG_ERROR("MmGetSystemRoutineAddress\n");
      return NULL;
    }
  }
  return functionPointer(ImageBase, RoutineName);
}
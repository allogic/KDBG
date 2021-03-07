#include "undoc.h"

PVOID PsGetProcessSectionBaseAddress(
  PEPROCESS Process)
{
  return GetSystemAddress<PSGETPROCESSSECTIONBASEADDRESS>(L"PsGetProcessSectionBaseAddress")(
    Process);
}

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

NTSTATUS RtlQueryModuleInformation(
  ULONG* InformationLength,
  ULONG SizePerModule,
  PVOID InformationBuffer)
{
  return GetSystemAddress<RTLQUERYMODULEINFORMATION>(L"RtlQueryModuleInformation")(
    InformationLength,
    SizePerModule,
    InformationBuffer);
}

PVOID RtlFindExportedRoutineByName(
  PVOID ImageBase,
  PSTR RoutineName)
{
  return GetSystemAddress<RTLFINDEXPORTEDROUTINEBYNAME>(L"RtlFindExportedRoutineByName")(
    ImageBase,
    RoutineName);
}
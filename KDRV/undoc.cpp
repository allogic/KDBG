#include "undoc.h"

/////////////////////////////////////////////////
/// NTOSKRNL
/////////////////////////////////////////////////

PVOID RtlFindExportedRoutineByName(
  PVOID ImageBase,
  PSTR RoutineName)
{
  return GetSystemRoutine<RTLFINDEXPORTEDROUTINEBYNAME>(L"RtlFindExportedRoutineByName")(
    ImageBase,
    RoutineName);
}

/////////////////////////////////////////////////
/// NTDLL
/////////////////////////////////////////////////

NTSTATUS ZwQuerySystemInformation(
  SYSTEM_INFORMATION_CLASS SystemInformationClass,
  PVOID SystemInformation,
  ULONG SystemInformationLength,
  PULONG ReturnLength)
{
  return GetSystemRoutine<ZWQUERYSYSTEMINFORMATION>(L"ZwQuerySystemInformation")(
    SystemInformationClass,
    SystemInformation,
    SystemInformationLength,
    ReturnLength);
}

/////////////////////////////////////////////////
/// Kernel Modules
/////////////////////////////////////////////////

NTSTATUS RtlQueryModuleInformation(
  ULONG* InformationLength,
  ULONG SizePerModule,
  PVOID InformationBuffer)
{
  return GetSystemRoutine<RTLQUERYMODULEINFORMATION>(L"RtlQueryModuleInformation")(
    InformationLength,
    SizePerModule,
    InformationBuffer);
}

/////////////////////////////////////////////////
/// User Modules
/////////////////////////////////////////////////

PPEB PsGetProcessPeb(
  PEPROCESS Process)
{
  return GetSystemRoutine<PSGETPROCESSPEB>(L"PsGetProcessPeb")(
    Process);
}
PVOID PsGetProcessSectionBaseAddress(
  PEPROCESS Process)
{
  return GetSystemRoutine<PSGETPROCESSSECTIONBASEADDRESS>(L"PsGetProcessSectionBaseAddress")(
    Process);
}

/////////////////////////////////////////////////
/// Thread
/////////////////////////////////////////////////

NTSTATUS PsSuspendProcess(
  PEPROCESS Process)
{
  return GetSystemRoutine<PSSUSPENDPROCESS>(L"PsSuspendProcess")(
    Process);
}
NTSTATUS PsResumeProcess(
  PEPROCESS Process)
{
  return GetSystemRoutine<PSRESUMEPROCESS>(L"PsResumeProcess")(
    Process);
}

NTSTATUS PsGetContextThread(
  PETHREAD Thread,
  PCONTEXT ThreadContext,
  KPROCESSOR_MODE Mode)
{
  return GetSystemRoutine<PSGETCONTEXTTHREAD>(L"PsGetContextThread")(
    Thread,
    ThreadContext,
    Mode);
}
NTSTATUS PsSetContextThread(
  PETHREAD Thread,
  PCONTEXT ThreadContext,
  KPROCESSOR_MODE Mode)
{
  return GetSystemRoutine<PSSETCONTEXTTHREAD>(L"PsSetContextThread")(
    Thread,
    ThreadContext,
    Mode);
}
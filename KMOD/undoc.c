#include "undoc.h"

ZWQUERYSYSTEMINFORMATION QSI = NULL;
PSGETCONTEXTTHREAD GCT = NULL;
PSSETCONTEXTTHREAD SCT = NULL;
PSGETPROCESSPEB GPP = NULL;

NTSTATUS
ZwQuerySystemInformation(
  SYSTEM_INFORMATION_CLASS SystemInformationClass,
  PVOID SystemInformation,
  ULONG SystemInformationLength,
  ULONG* ReturnLength)
{
  if (!QSI)
  {
    UNICODE_STRING functionName;
    RtlInitUnicodeString(&functionName, L"ZwQuerySystemInformation");
    QSI = (ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&functionName);
  }
  return QSI(
    SystemInformationClass,
    SystemInformation,
    SystemInformationLength,
    ReturnLength);
}

NTSTATUS
PsGetContextThread(
  PETHREAD Thread,
  PCONTEXT ThreadContext,
  KPROCESSOR_MODE Mode)
{
  if (!GCT)
  {
    UNICODE_STRING functionName;
    RtlInitUnicodeString(&functionName, L"PsGetContextThread");
    GCT = (PSGETCONTEXTTHREAD)MmGetSystemRoutineAddress(&functionName);
  }
  return GCT(
    Thread,
    ThreadContext,
    Mode);
}

NTSTATUS
PsSetContextThread(
  PETHREAD Thread,
  PCONTEXT ThreadContext,
  KPROCESSOR_MODE Mode)
{
  if (!SCT)
  {
    UNICODE_STRING functionName;
    RtlInitUnicodeString(&functionName, L"PsSetContextThread");
    SCT = (PSSETCONTEXTTHREAD)MmGetSystemRoutineAddress(&functionName);
  }
  return SCT(
    Thread,
    ThreadContext,
    Mode);
}

PPEB
PsGetProcessPeb(
  PEPROCESS process)
{
  if (!GPP)
  {
    UNICODE_STRING functionName;
    RtlInitUnicodeString(&functionName, L"PsGetProcessPeb");
    GPP = (PSGETPROCESSPEB)MmGetSystemRoutineAddress(&functionName);
  }
  return GPP(
    process);
}
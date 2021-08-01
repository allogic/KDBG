#include "undoc.h"

NTSTATUS
ZwQuerySystemInformation(
  SYSTEM_INFORMATION_CLASS SystemInformationClass,
  PVOID SystemInformation,
  ULONG SystemInformationLength,
  ULONG* ReturnLength)
{
  return KmGetSystemRoutine<ZWQUERYSYSTEMINFORMATION>(L"ZwQuerySystemInformation")(
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
  return KmGetSystemRoutine<PSGETCONTEXTTHREAD>(L"PsGetContextThread")(
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
  return KmGetSystemRoutine<PSSETCONTEXTTHREAD>(L"PsSetContextThread")(
    Thread,
    ThreadContext,
    Mode);
}

PPEB
PsGetProcessPeb(
  PEPROCESS process)
{
  return KmGetSystemRoutine<PSGETPROCESSPEB>(L"PsGetProcessPeb")(
    process);
}
#include "krnl.h"

NTSTATUS ZwQuerySystemInformation(
  SYSTEM_INFORMATION_CLASS SystemInformationClass,
  PVOID SystemInformation,
  ULONG SystemInformationLength,
  ULONG* ReturnLength)
{
  return GetSystemRoutine<ZWQUERYSYSTEMINFORMATION>(L"ZwQuerySystemInformation")(
    SystemInformationClass,
    SystemInformation,
    SystemInformationLength,
    ReturnLength);
}

NTSTATUS PsGetContextThread(
  PETHREAD Thread,
  PCONTEXT ThreadContext,
  KPROCESSOR_MODE Mode)
{
  return GetSystemRoutine<PSGETTHREADCONTEXT>(L"PsGetContextThread")(
    Thread,
    ThreadContext,
    Mode);
}
NTSTATUS PsSetContextThread(
  PETHREAD Thread,
  PCONTEXT ThreadContext,
  KPROCESSOR_MODE Mode)
{
  return GetSystemRoutine<PSSETTHREADCONTEXT>(L"PsSetContextThread")(
    Thread,
    ThreadContext,
    Mode);
}
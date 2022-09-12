#include <km_undoc.h>

///////////////////////////////////////////////////////////
// Locals
///////////////////////////////////////////////////////////

static ZWQUERYSYSTEMINFORMATION s_QSI = NULL;
static PSGETPROCESSPEB s_GPP = NULL;

///////////////////////////////////////////////////////////
// Ntoskrnl utilities
///////////////////////////////////////////////////////////

NTSTATUS
ZwQuerySystemInformation(
  SYSTEM_INFORMATION_CLASS SystemInformationClass,
  PVOID SystemInformation,
  ULONG SystemInformationLength,
  ULONG* ReturnLength)
{
  if (s_QSI == FALSE)
  {
    UNICODE_STRING functionName = RTL_CONSTANT_STRING(L"ZwQuerySystemInformation");
    s_QSI = (ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&functionName);
  }
  return s_QSI(
    SystemInformationClass,
    SystemInformation,
    SystemInformationLength,
    ReturnLength);
}

PPEB
PsGetProcessPeb(
  PEPROCESS process)
{
  if (s_GPP == FALSE)
  {
    UNICODE_STRING functionName = RTL_CONSTANT_STRING(L"PsGetProcessPeb");
    s_GPP = (PSGETPROCESSPEB)MmGetSystemRoutineAddress(&functionName);
  }
  return s_GPP(
    process);
}
#include "ulogic.h"
#include "undoc.h"

NTSTATUS DumpUserImages(ULONG pid, PVOID images)
{
  UNREFERENCED_PARAMETER(pid);
  UNREFERENCED_PARAMETER(images);
  NTSTATUS status = STATUS_SUCCESS;
  return status;
}
NTSTATUS GetUserImageBase(ULONG pid, PPVOID imageBase)
{
  NTSTATUS status = STATUS_SUCCESS;
  // Find process
  PEPROCESS process = NULL;
  status = PsLookupProcessByProcessId((HANDLE)pid, &process);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("PsLookupProcessByProcessId\n");
    return status;
  }
  // Find base address
  *imageBase = PsGetProcessSectionBaseAddress(process);
  if (*imageBase)
  {
    ObDereferenceObject(process);
    LOG_ERROR("PsGetProcessSectionBaseAddress\n");
    return STATUS_INVALID_ADDRESS;
  }
  ObDereferenceObject(process);
  return status;
}

NTSTATUS TryReadUserMemory(ULONG pid, PVOID base, PUCHAR buffer, ULONG bufferSize)
{
  UNREFERENCED_PARAMETER(pid);
  UNREFERENCED_PARAMETER(base);
  UNREFERENCED_PARAMETER(buffer);
  UNREFERENCED_PARAMETER(bufferSize);
  NTSTATUS status = STATUS_SUCCESS;
  return status;
}
NTSTATUS TryWriteUserMemory(ULONG pid, PVOID base, PUCHAR buffer, ULONG bufferSize)
{
  UNREFERENCED_PARAMETER(pid);
  UNREFERENCED_PARAMETER(base);
  UNREFERENCED_PARAMETER(buffer);
  UNREFERENCED_PARAMETER(bufferSize);
  NTSTATUS status = STATUS_SUCCESS;
  return status;
}
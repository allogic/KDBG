#include "ulogic.h"

NTSTATUS DumpUserImages(ULONG pid, ULONG numModules)
{
  UNREFERENCED_PARAMETER(pid);
  UNREFERENCED_PARAMETER(numModules);
  NTSTATUS status = STATUS_SUCCESS;
  return status;
}
NTSTATUS GetUserImageBase(PCHAR imageName, PPVOID imageBase, PULONG imageSize)
{
  UNREFERENCED_PARAMETER(imageName);
  UNREFERENCED_PARAMETER(imageBase);
  UNREFERENCED_PARAMETER(imageSize);
  NTSTATUS status = STATUS_SUCCESS;
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
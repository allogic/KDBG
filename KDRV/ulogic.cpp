#include "ulogic.h"
#include "undoc.h"
#include "pe.h"

NTSTATUS GetUserImages(PSYSTEM_PROCESS_INFORMATION images, ULONG size)
{
  NTSTATUS status = STATUS_SUCCESS;
  // Query user images
  status = ZwQuerySystemInformation(SystemProcessInformation, images, size, NULL);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("ZwQuerySystemInformation\n");
    return status;
  }
  return status;
}
NTSTATUS GetUserImageBase(ULONG pid, PVOID& imageBase)
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
  // Try attach to target process
  KAPC_STATE apc;
  __try
  {
    KeStackAttachProcess(process, &apc);
    // Find base address
    imageBase = PsGetProcessSectionBaseAddress(process);
    if (imageBase)
    {
      LOG_INFO("found image base at %p", imageBase);
      // Find PEB struct
      PPEB64 peb64 = (PPEB64)PsGetProcessPeb(process);
      if (peb64)
      {
        LOG_INFO("found peb64\n");
        // Obtain data table entry
        PLDR_DATA_TABLE_ENTRY mainMod = GetMainModuleDataTableEntry(peb64);
        if (mainMod)
        {
          LOG_INFO("found ldr data table entry\n");
          // Log some infos
          LOG_INFO("%p %ws\n", mainMod->DllBase, mainMod->FullDllName.Buffer);
        }
      }
    }
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    LOG_ERROR("Something went wrong\n");
    status = STATUS_FAIL_CHECK;
  }
  // Cleanup
  KeUnstackDetachProcess(&apc);
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
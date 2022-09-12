#include <km_scanner.h>
#include <km_debug.h>
#include <km_config.h>

///////////////////////////////////////////////////////////
// Locals
///////////////////////////////////////////////////////////

static LIST_ENTRY g_scans;
static DWORD32 g_scanCount;

///////////////////////////////////////////////////////////
// Scanner data types
///////////////////////////////////////////////////////////

typedef struct _SCAN_ENTRY
{
  LIST_ENTRY List;
  DWORD64 Base;
} SCAN_ENTRY, * PSCAN_ENTRY;

///////////////////////////////////////////////////////////
// Scanner API
///////////////////////////////////////////////////////////

NTSTATUS
KmInitializeScanList()
{
  NTSTATUS status = STATUS_SUCCESS;

  // Reset scan list
  InitializeListHead(&g_scans);

  // Reset scan count
  g_scanCount = 0;

  return status;
}

NTSTATUS
KmResetScanList()
{
  NTSTATUS status = STATUS_SUCCESS;

  // Free entries
  while (IsListEmpty(&g_scans) == FALSE)
  {
    PLIST_ENTRY listEntry = RemoveHeadList(&g_scans);
    PSCAN_ENTRY scanEntry = CONTAINING_RECORD(listEntry, SCAN_ENTRY, List);
    ExFreePoolWithTag(scanEntry, KM_MEMORY_POOL_TAG);
  }

  // Reset scan list
  InitializeListHead(&g_scans);

  // Reset scan count
  g_scanCount = 0;

  return status;
}

NTSTATUS
KmScanProcessFirst(
  PSCAN_PROCESS_FIRST request,
  PDWORD32 count)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;

  __try
  {
    // Reset scan results
    status = KmResetScanList();
    if (NT_SUCCESS(status))
    {
      // Allocate buffer to hold bytes while attached to process
      PBYTE buffer = ExAllocatePoolWithTag(NonPagedPool, request->Size, KM_MEMORY_POOL_TAG);
      if (buffer)
      {
        // Copy bytes into buffer
        RtlCopyMemory(buffer, request->Buffer, request->Size);

        // Search process by process id
        PEPROCESS process;
        status = PsLookupProcessByProcessId((HANDLE)request->Pid, &process);
        if (NT_SUCCESS(status))
        {
          // Attach to process
          KAPC_STATE apc;
          KeStackAttachProcess(process, &apc);

          // Setup memory information
          MEMORY_BASIC_INFORMATION mbi;
          mbi.BaseAddress = (PVOID)request->Base;

          // Iterate process memory regions
          while (NT_SUCCESS(ZwQueryVirtualMemory(ZwCurrentProcess(), mbi.BaseAddress, MemoryBasicInformation, &mbi, sizeof(mbi), NULL)))
          {
            // Skip non-committed, no-access and guard pages
            if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS && (mbi.Protect & PAGE_GUARD) == FALSE)
            {
              // Create MDL for supplied range
              PMDL mdl = IoAllocateMdl(mbi.BaseAddress, (DWORD32)mbi.RegionSize, FALSE, FALSE, NULL); // TODO: Fix me! (Convert address space to user mode, which is possible since we are attached)
              if (mdl)
              {
                __try
                {
                  // Try lock pages
                  MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
                  status = STATUS_SUCCESS;
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                  status = STATUS_INVALID_USER_BUFFER;
                }

                if (NT_SUCCESS(status))
                {
                  // Remap to system space address
                  PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, HighPagePriority);
                  if (mapped)
                  {
                    // Set page protection
                    status = MmProtectMdlSystemAddress(mdl, PAGE_READONLY);
                    if (NT_SUCCESS(status))
                    {
                      // Scan region
                      for (DWORD64 base = (DWORD64)mapped; base <= ((DWORD64)mapped + mbi.RegionSize - request->Size); base += request->Size) // TODO: Fix me! (Double check loop range)
                      {
                        switch (request->Type)
                        {
                          case SCAN_TYPE_BYTE8:
                          {
                            if (*(PINT8)base == *(PINT8)buffer)
                            {
                              // Insert scan result
                              PSCAN_ENTRY scanEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(SCAN_ENTRY), KM_MEMORY_POOL_TAG);
                              scanEntry->Base = base;
                              InsertTailList(&g_scans, &scanEntry->List);

                              // Increment scan count
                              g_scanCount++;
                            }
                            break;
                          }
                          case SCAN_TYPE_BYTE16:
                          {
                            if (*(PINT16)base == *(PINT16)buffer)
                            {
                              // Insert scan result
                              PSCAN_ENTRY scanEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(SCAN_ENTRY), KM_MEMORY_POOL_TAG);
                              scanEntry->Base = base;
                              InsertTailList(&g_scans, &scanEntry->List);

                              // Increment scan count
                              g_scanCount++;
                            }
                            break;
                          }
                          case SCAN_TYPE_BYTE32:
                          {
                            if (*(PINT32)base == *(PINT32)buffer)
                            {
                              // Insert scan result
                              PSCAN_ENTRY scanEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(SCAN_ENTRY), KM_MEMORY_POOL_TAG);
                              scanEntry->Base = base;
                              InsertTailList(&g_scans, &scanEntry->List);

                              // Increment scan count
                              g_scanCount++;
                            }
                            break;
                          }
                          case SCAN_TYPE_BYTE64:
                          {
                            if (*(PINT64)base == *(PINT64)buffer)
                            {
                              // Insert scan result
                              PSCAN_ENTRY scanEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(SCAN_ENTRY), KM_MEMORY_POOL_TAG);
                              scanEntry->Base = base;
                              InsertTailList(&g_scans, &scanEntry->List);

                              // Increment scan count
                              g_scanCount++;
                            }
                            break;
                          }
                        }
                      }
                    }

                    // Unmap locked pages
                    MmUnmapLockedPages(mapped, mdl);
                  }

                  // Unlock MDL
                  MmUnlockPages(mdl);
                }

                // Free MDL
                IoFreeMdl(mdl);
              }
            }

            // Jump to next region
            mbi.BaseAddress = (PVOID)((DWORD64)mbi.BaseAddress + mbi.RegionSize);
          }

          // Detach from process
          KeUnstackDetachProcess(&apc);

          // Dereference process handle
          ObDereferenceObject(process);
        }

        // Free buffer
        ExFreePoolWithTag(buffer, KM_MEMORY_POOL_TAG);
      }

      // Write occurrence count
      *count = g_scanCount;
    }
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    KD_LOG("Something went wrong\n");
    status = STATUS_UNHANDLED_EXCEPTION;
  }

  return status;
}

NTSTATUS
KmScanProcessNext(
  PSCAN_PROCESS_NEXT request)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  UNREFERENCED_PARAMETER(request);
  return status;
}

NTSTATUS
KmReadScanList(
  DWORD32 count,
  PDWORD64 scans)
{
  NTSTATUS status = STATUS_SUCCESS;

  __try
  {
    // Iterate scans
    DWORD32 i = 0;
    PLIST_ENTRY listEntry = g_scans.Flink;
    while (listEntry != &g_scans)
    {
      // Copy scan
      PSCAN_ENTRY scanEntry = CONTAINING_RECORD(listEntry, SCAN_ENTRY, List);
      scans[i] = scanEntry->Base;

      // Increment to next record
      i++;
      listEntry = listEntry->Flink;

      // Break if list exceeds buffer
      if (i > count)
      {
        break;
      }
    }
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    KD_LOG("Something went wrong\n");
    status = STATUS_UNHANDLED_EXCEPTION;
  }

  return status;
}
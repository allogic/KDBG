#include <km_process_image.h>
#include <km_debug.h>
#include <km_config.h>
#include <km_memory.h>
#include <km_undoc.h>

///////////////////////////////////////////////////////////
// Locals
///////////////////////////////////////////////////////////

static LIST_ENTRY g_images;
static DWORD32 g_imageCount;

///////////////////////////////////////////////////////////
// Process image data types
///////////////////////////////////////////////////////////

typedef struct _IMAGE_ENTRY
{
  LIST_ENTRY List;
  DWORD64 Base;
  DWORD32 Size;
  WCHAR Name[260];
  USHORT NameSize;
} IMAGE_ENTRY, * PIMAGE_ENTRY;

///////////////////////////////////////////////////////////
// Process image API
///////////////////////////////////////////////////////////

NTSTATUS
KmInitializeProcessImageList()
{
  NTSTATUS status = STATUS_SUCCESS;

  // Reset image list
  InitializeListHead(&g_images);

  // Reset image count
  g_imageCount = 0;

  return status;
}

NTSTATUS
KmResetProcessImageList()
{
  NTSTATUS status = STATUS_SUCCESS;

  // Free entries
  while (IsListEmpty(&g_images) == FALSE)
  {
    PLIST_ENTRY listEntry = RemoveHeadList(&g_images);
    PIMAGE_ENTRY imageEntry = CONTAINING_RECORD(listEntry, IMAGE_ENTRY, List);
    ExFreePoolWithTag(imageEntry, KM_MEMORY_POOL_TAG);
  }

  // Reset image list
  InitializeListHead(&g_images);

  // Reset image count
  g_imageCount = 0;

  return status;
}

NTSTATUS
KmUpdateProcessImages(
  DWORD32 pid,
  PDWORD32 count)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;

  __try
  {
    // Reset image results
    status = KmResetProcessImageList();
    if (NT_SUCCESS(status))
    {
      // Search process by process id
      PEPROCESS process;
      status = PsLookupProcessByProcessId((HANDLE)pid, &process);
      if (NT_SUCCESS(status))
      {
        // Attach to process
        KAPC_STATE apc;
        KeStackAttachProcess(process, &apc);

        // Get process PEB
        PPEB64 peb = (PPEB64)PsGetProcessPeb(process);
        if (peb)
        {
          // Iterate process images
          PLIST_ENTRY listEntry = peb->Ldr->InMemoryOrderModuleList.Flink;
          while (listEntry != &peb->Ldr->InMemoryOrderModuleList)
          {
            PLDR_DATA_TABLE_ENTRY moduleEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            if (moduleEntry && moduleEntry->DllBase)
            {
              // Insert image
              PIMAGE_ENTRY imageEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(IMAGE_ENTRY), KM_MEMORY_POOL_TAG);
              status = KmReadMemorySafe(&imageEntry->Base, &moduleEntry->DllBase, sizeof(DWORD64));
              status = KmReadMemorySafe(&imageEntry->Size, &moduleEntry->SizeOfImage, sizeof(DWORD32));
              status = KmReadMemorySafe(imageEntry->Name, moduleEntry->BaseDllName.Buffer, moduleEntry->BaseDllName.Length);
              status = KmReadMemorySafe(&imageEntry->NameSize, &moduleEntry->BaseDllName.Length, sizeof(USHORT));
              InsertTailList(&g_images, &imageEntry->List);

              // Increment image count
              g_imageCount++;
            }
            listEntry = listEntry->Flink;
          }
        }

        // Detach from process
        KeUnstackDetachProcess(&apc);

        // Dereference process handle
        ObDereferenceObject(process);

        // Write occurrence count
        *count = g_imageCount;
      }
    }
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    KD_LOG("Something went wrong\n");
  }

  return status;
}

NTSTATUS
KmReadProcessImageList(
  DWORD32 count,
  PPROCESS_IMAGE images)
{
  NTSTATUS status = STATUS_SUCCESS;

  __try
  {
    // Iterate images
    DWORD32 i = 0;
    PLIST_ENTRY listEntry = g_images.Flink;
    while (listEntry != &g_images)
    {
      // Copy image
      PIMAGE_ENTRY imageEntry = CONTAINING_RECORD(listEntry, IMAGE_ENTRY, List);
      images[i].Base = imageEntry->Base;
      images[i].Size = imageEntry->Size;
      RtlCopyMemory(images[i].Name, imageEntry->Name, imageEntry->NameSize);

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
#include <km_kernel_image.h>
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
// Kernel image data types
///////////////////////////////////////////////////////////

typedef struct _IMAGE_ENTRY
{
  LIST_ENTRY List;
  DWORD64 Base;
  DWORD32 Size;
  CHAR Name[260];
  USHORT NameSize;
} IMAGE_ENTRY, * PIMAGE_ENTRY;

///////////////////////////////////////////////////////////
// Kernel image API
///////////////////////////////////////////////////////////

NTSTATUS
KmInitializeKernelImageList()
{
  NTSTATUS status = STATUS_SUCCESS;

  // Reset image list
  InitializeListHead(&g_images);

  // Reset image count
  g_imageCount = 0;

  return status;
}

NTSTATUS
KmResetKernelImageList()
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
KmUpdateKernelImages(
  PDWORD32 count)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;

  __try
  {
    // Reset image results
    status = KmResetKernelImageList();
    if (NT_SUCCESS(status))
    {
      // Allocate buffer to hold images
      PRTL_PROCESS_MODULES buffer = ExAllocatePoolWithTag(NonPagedPool, sizeof(RTL_PROCESS_MODULES) * 0x400 * 0x400, KM_MEMORY_POOL_TAG);
      if (buffer)
      {
        // Zero buffer
        RtlFillMemory(buffer, sizeof(RTL_PROCESS_MODULES) * 0x400 * 0x400, 0);

        // Use undocumented function to retrieve kernel modules
        status = ZwQuerySystemInformation(SystemModuleInformation, buffer, sizeof(RTL_PROCESS_MODULES) * 0x400 * 0x400, NULL);
        if (NT_SUCCESS(status))
        {
          // Iterate kernel images
          for (DWORD32 i = 0; i < buffer[0].NumberOfModules; i++)
          {
            // Insert image
            PIMAGE_ENTRY imageEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(IMAGE_ENTRY), KM_MEMORY_POOL_TAG);
            status = KmReadMemorySafe(&imageEntry->Base, &buffer[0].Modules[i].ImageBase, sizeof(DWORD64));
            status = KmReadMemorySafe(&imageEntry->Size, &buffer[0].Modules[i].ImageSize, sizeof(DWORD32));
            status = KmReadMemorySafe(imageEntry->Name, buffer[0].Modules[i].FullPathName + buffer[0].Modules[i].OffsetToFileName, (DWORD32)strlen((PCHAR)(buffer[0].Modules[i].FullPathName + buffer[0].Modules[i].OffsetToFileName)));
            imageEntry->NameSize = (USHORT)strlen((PCHAR)(buffer[0].Modules[i].FullPathName + buffer[0].Modules[i].OffsetToFileName));
            InsertTailList(&g_images, &imageEntry->List);

            // Increment image count
            g_imageCount++;
          }
        }

        // Free buffer
        ExFreePoolWithTag(buffer, KM_MEMORY_POOL_TAG);

        // Write occurrence count
        *count = g_imageCount;
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

NTSTATUS
KmReadKernelImageList(
  DWORD32 count,
  PKERNEL_IMAGE images)
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
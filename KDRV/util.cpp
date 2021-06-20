#include "util.h"

NTSTATUS DumpToFile(PUNICODE_STRING filePath, PVOID bytes, ULONG size)
{
  NTSTATUS status = STATUS_SUCCESS;
  OBJECT_ATTRIBUTES objectAttributes;
  HANDLE file;
  IO_STATUS_BLOCK ioStatusBlock;
  InitializeObjectAttributes(&objectAttributes, filePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
  status = ZwCreateFile(&file, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("ZwCreateFile\n");
    return status;
  }
  status = ZwWriteFile(file, NULL, NULL, NULL, &ioStatusBlock, bytes, size, NULL, NULL);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("ZwWriteFile");
    return status;
  }
  status = ZwClose(file);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("ZwClose");
    return status;
  }
  return status;
}
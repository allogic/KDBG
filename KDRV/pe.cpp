#include "pe.h"

ULONG RvaToSection(PIMAGE_NT_HEADERS ntHeaders, ULONG rva)
{
  PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
  USHORT numSections = ntHeaders->FileHeader.NumberOfSections;
  for (INT i = 0; i < numSections; i++)
    if (sectionHeader[i].VirtualAddress <= rva)
      if ((sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) > rva)
        return i;
  return PE_ERROR_VALUE;
}
ULONG RvaToOffset(PIMAGE_NT_HEADERS ntHeaders, ULONG rva, ULONG fileSize)
{
  PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
  USHORT numSections = ntHeaders->FileHeader.NumberOfSections;
  for (INT i = 0; i < numSections; i++)
    if (sectionHeader[i].VirtualAddress <= rva)
      if ((sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) > rva)
      {
        rva -= sectionHeader[i].VirtualAddress;
        rva += sectionHeader[i].PointerToRawData;
        return rva < fileSize ? rva : PE_ERROR_VALUE;
      }
  return PE_ERROR_VALUE;
}

NTSTATUS GetKernelImages(PRTL_PROCESS_MODULES images, ULONG size)
{
  NTSTATUS status = STATUS_SUCCESS;
  // Query kernel images
  status = ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, images, size, NULL);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("ZwQuerySystemInformation\n");
    return status;
  }
  __try
  {
    for (ULONG i = 0; i < images[0].NumberOfModules; ++i)
      LOG_INFO("%p %s\n", images[0].Modules[i].ImageBase, images[0].Modules[i].FullPathName);
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {

  }
  return status;
}
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
  __try
  {
    for (ULONG i = 0; i < size; ++i)
      LOG_INFO("%p %wZ\n", (PVOID)0, &images[i].ImageName);
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {

  }
  return status;
}

NTSTATUS GetKernelImageBase(PCHAR imageName, PVOID& imageBase)
{
  NTSTATUS status = STATUS_SUCCESS;
  // Optain memory for image module infos
  PRTL_PROCESS_MODULES images = (PRTL_PROCESS_MODULES)RtlAllocateMemory(TRUE, sizeof(RTL_PROCESS_MODULES) * 1024 * 1024);
  if (!images)
  {
    LOG_ERROR("RtlAllocateMemory\n");
    return STATUS_INVALID_ADDRESS;
  }
  // Query image module infos - SystemModuleInformation(11)
  status = ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, images, 1024 * 1024, NULL);
  if (!NT_SUCCESS(status))
  {
    RtlFreeMemory(images);
    LOG_ERROR("ZwQuerySystemInformation\n");
    return status;
  }
  // Find image
  for (SIZE_T i = 0; i < images[0].NumberOfModules; ++i)
    if (strcmp(imageName, (PCHAR)(images[0].Modules[i].FullPathName + images[0].Modules[i].OffsetToFileName)) == 0)
    {
      imageBase = images[0].Modules[i].ImageBase;
      break;
    }
  // Cleanup
  RtlFreeMemory(images);
  return status;
}
NTSTATUS GetUserImageBase(ULONG pid, PWCHAR moduleName, PVOID& imageBase)
{
  UNREFERENCED_PARAMETER(moduleName);
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
    // Find PEB struct
    PPEB64 peb64 = (PPEB64)PsGetProcessPeb(process);
    if (peb64)
    {
      // Obtain data table entry
      PLDR_DATA_TABLE_ENTRY modules = GetMainModuleDataTableEntry(peb64);
      // Temporarly let the first image to be the target
      imageBase = modules->DllBase;
      // Traverse the list header of the module linked list
      PLDR_DATA_TABLE_ENTRY module = NULL;
      PLIST_ENTRY moduleList = modules->InLoadOrderLinks.Flink;
      PLIST_ENTRY moduleEntry = moduleList->Flink;
      while (moduleEntry != moduleList)
      {
        module = CONTAINING_RECORD(moduleEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (&module->BaseDllName.Buffer != 0)
        {
          //LOG_INFO("%wZ\n", &module->BaseDllName);
          //UNICODE_STRING dllName;
          //RtlInitUnicodeString(&dllName, moduleName);
          //if (RtlCompareUnicodeString(&dllName, &module->BaseDllName, TRUE) == 0)
          //{
          //  LOG_INFO("Target module found %wZ\n", &module->BaseDllName);
          //  imageBase = module->DllBase;
          //}
        }
        // Point to the next linked list
        moduleEntry = moduleEntry->Flink;
      }
    }
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    LOG_ERROR("Something went wrong\n");
    status = STATUS_FAIL_CHECK;
  }
  // Compare pointer and status
  if (!imageBase)
    status = STATUS_INVALID_ADDRESS;
  // Cleanup
  KeUnstackDetachProcess(&apc);
  ObDereferenceObject(process);
  return status;
}

PVOID GetPageBase(PVOID header, PULONG size, PVOID ptr)
{
  if ((PUCHAR)ptr < (PUCHAR)header)
    return NULL;

  ULONG rva = (ULONG)((PUCHAR)ptr - (PUCHAR)header);
  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)header;

  if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
  {
    LOG_ERROR("Invalid IMAGE_DOS_SIGNATURE\n");
    return NULL;
  }

  PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)header + pDosHeader->e_lfanew);

  if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
  {
    LOG_ERROR("Invalid IMAGE_NT_SIGNATURE\n");
    return NULL;
  }

  PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
  INT section = RvaToSection(pNtHeaders, rva);

  if (section == PE_ERROR_VALUE)
    return NULL;

  if (size)
    *size = pSectionHeader[section].SizeOfRawData;

  return (PVOID)((PUCHAR)header + pSectionHeader[section].VirtualAddress);
}
ULONG GetExportOffset(PVOID imageBase, ULONG fileSize, PCCHAR exportName)
{
  PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;

  if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
  {
    LOG_ERROR("Invalid IMAGE_DOS_SIGNATURE\n");
    return PE_ERROR_VALUE;
  }

  PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)imageBase + dosHeader->e_lfanew);

  if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
  {
    LOG_ERROR("Invalid IMAGE_NT_SIGNATURE\n");
    return PE_ERROR_VALUE;
  }

  PIMAGE_DATA_DIRECTORY dataDir;

  if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
  {
    dataDir = ((PIMAGE_NT_HEADERS64)ntHeaders)->OptionalHeader.DataDirectory;
  }
  else
  {
    dataDir = ((PIMAGE_NT_HEADERS32)ntHeaders)->OptionalHeader.DataDirectory;
  }

  ULONG exportDirRva = dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  ULONG exportDirSize = dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
  ULONG exportDirOffset = RvaToOffset(ntHeaders, exportDirRva, fileSize);

  if (exportDirOffset == PE_ERROR_VALUE)
  {
    LOG_ERROR("Invalid export directory\n");
    return PE_ERROR_VALUE;
  }

  PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)imageBase + exportDirOffset);

  ULONG numOfNames = exportDir->NumberOfNames;
  ULONG addressOfFunctionsOffset = RvaToOffset(ntHeaders, exportDir->AddressOfFunctions, fileSize);
  ULONG addressOfNameOrdinalsOffset = RvaToOffset(ntHeaders, exportDir->AddressOfNameOrdinals, fileSize);
  ULONG addressOfNamesOffset = RvaToOffset(ntHeaders, exportDir->AddressOfNames, fileSize);

  if (addressOfFunctionsOffset == PE_ERROR_VALUE || addressOfNameOrdinalsOffset == PE_ERROR_VALUE || addressOfNamesOffset == PE_ERROR_VALUE)
  {
    LOG_ERROR("Invalid export directory content\n");
    return PE_ERROR_VALUE;
  }

  PULONG addressOfFunctions = (PULONG)((PUCHAR)imageBase + addressOfFunctionsOffset);
  PUSHORT addressOfNameOrdinals = (PUSHORT)((PUCHAR)imageBase + addressOfNameOrdinalsOffset);
  PULONG addressOfNames = (PULONG)((PUCHAR)imageBase + addressOfNamesOffset);

  ULONG exportOffset = PE_ERROR_VALUE;

  for (ULONG i = 0; i < numOfNames; i++)
  {
    ULONG currentNameOffset = RvaToOffset(ntHeaders, addressOfNames[i], fileSize);

    if (currentNameOffset == PE_ERROR_VALUE)
      continue;

    PCCHAR pCurrentName = (PCCHAR)((PUCHAR)imageBase + currentNameOffset);
    ULONG currentFunctionRva = addressOfFunctions[addressOfNameOrdinals[i]];

    if (currentFunctionRva >= exportDirRva && currentFunctionRva < exportDirRva + exportDirSize)
      continue;

    if (strcmp(pCurrentName, exportName) == 0)
    {
      exportOffset = RvaToOffset(ntHeaders, currentFunctionRva, fileSize);
      break;
    }
  }

  if (exportOffset == PE_ERROR_VALUE)
  {
    LOG_ERROR("Export %s not found\n", exportName);
    return PE_ERROR_VALUE;
  }

  return exportOffset;
}

PLDR_DATA_TABLE_ENTRY GetMainModuleDataTableEntry(PPEB64 peb)
{
  if (SanitizeUserPointer(peb, sizeof(PEB64)))
  {
    if (peb->Ldr)
    {
      if (SanitizeUserPointer(peb->Ldr, sizeof(PEB_LDR_DATA)))
      {
        if (!peb->Ldr->Initialized)
        {
          int initLoadCount = 0;

          while (!peb->Ldr->Initialized && initLoadCount++ < 4)
          {
            DriverSleep(250);
          }
        }

        if (peb->Ldr->Initialized)
        {
          return CONTAINING_RECORD(peb->Ldr->InLoadOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        }
      }
    }
  }
  return NULL;
}
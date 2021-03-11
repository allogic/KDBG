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
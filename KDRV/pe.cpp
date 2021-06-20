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

PVOID GetPageBase(PVOID moduleBase, PULONG moduleSize, PVOID ptr)
{
  if ((PUCHAR)ptr < (PUCHAR)moduleBase)
    return NULL;
  ULONG rva = (ULONG)((PUCHAR)ptr - (PUCHAR)moduleBase);
  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)moduleBase;
  if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
  {
    LOG_ERROR("Invalid IMAGE_DOS_SIGNATURE\n");
    return NULL;
  }
  PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)moduleBase + pDosHeader->e_lfanew);
  if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
  {
    LOG_ERROR("Invalid IMAGE_NT_SIGNATURE\n");
    return NULL;
  }
  PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
  INT section = RvaToSection(pNtHeaders, rva);
  if (section == PE_ERROR_VALUE)
    return NULL;
  if (ptr)
    *moduleSize = pSectionHeader[section].SizeOfRawData;
  return (PVOID)((PUCHAR)moduleBase + pSectionHeader[section].VirtualAddress);
}
ULONG GetExportOffset(PVOID moduleBase, ULONG moduleSize, PCCHAR exportName)
{
  PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
  if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
  {
    LOG_ERROR("Invalid IMAGE_DOS_SIGNATURE\n");
    return PE_ERROR_VALUE;
  }
  PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)moduleBase + dosHeader->e_lfanew);
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
  ULONG exportDirOffset = RvaToOffset(ntHeaders, exportDirRva, moduleSize);
  if (exportDirOffset == PE_ERROR_VALUE)
  {
    LOG_ERROR("Invalid export directory\n");
    return PE_ERROR_VALUE;
  }
  PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)moduleBase + exportDirOffset);
  ULONG numOfNames = exportDir->NumberOfNames;
  ULONG addressOfFunctionsOffset = RvaToOffset(ntHeaders, exportDir->AddressOfFunctions, moduleSize);
  ULONG addressOfNameOrdinalsOffset = RvaToOffset(ntHeaders, exportDir->AddressOfNameOrdinals, moduleSize);
  ULONG addressOfNamesOffset = RvaToOffset(ntHeaders, exportDir->AddressOfNames, moduleSize);
  if (addressOfFunctionsOffset == PE_ERROR_VALUE || addressOfNameOrdinalsOffset == PE_ERROR_VALUE || addressOfNamesOffset == PE_ERROR_VALUE)
  {
    LOG_ERROR("Invalid export directory content\n");
    return PE_ERROR_VALUE;
  }
  PULONG addressOfFunctions = (PULONG)((PUCHAR)moduleBase + addressOfFunctionsOffset);
  PUSHORT addressOfNameOrdinals = (PUSHORT)((PUCHAR)moduleBase + addressOfNameOrdinalsOffset);
  PULONG addressOfNames = (PULONG)((PUCHAR)moduleBase + addressOfNamesOffset);
  ULONG exportOffset = PE_ERROR_VALUE;
  for (ULONG i = 0; i < numOfNames; i++)
  {
    ULONG currentNameOffset = RvaToOffset(ntHeaders, addressOfNames[i], moduleSize);
    if (currentNameOffset == PE_ERROR_VALUE)
      continue;
    PCCHAR pCurrentName = (PCCHAR)((PUCHAR)moduleBase + currentNameOffset);
    ULONG currentFunctionRva = addressOfFunctions[addressOfNameOrdinals[i]];
    if (currentFunctionRva >= exportDirRva && currentFunctionRva < exportDirRva + exportDirSize)
      continue;
    if (strcmp(pCurrentName, exportName) == 0)
    {
      exportOffset = RvaToOffset(ntHeaders, currentFunctionRva, moduleSize);
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
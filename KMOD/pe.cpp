#include "pe.h"

PPEB PsGetProcessPeb(
  PEPROCESS process)
{
  return GetSystemRoutine<PSGETPROCESSPEB>(L"PsGetProcessPeb")(
    process);
}

USHORT RvaToSection(PIMAGE_NT_HEADERS ntHeaders, PVOID rva)
{
  PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
  USHORT numSections = ntHeaders->FileHeader.NumberOfSections;
  for (USHORT i = 0; i < numSections; ++i)
    if (sectionHeader[i].VirtualAddress <= (ULONG64)rva)
      if ((sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) > (ULONG64)rva)
        return i;
  return (USHORT)KMOD_PE_ERROR_VALUE;
}
ULONG RvaToOffset(PIMAGE_NT_HEADERS ntHeaders, PVOID rva, ULONG imageSize)
{
  PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
  USHORT numSections = ntHeaders->FileHeader.NumberOfSections;
  for (USHORT i = 0; i < numSections; ++i)
    if (sectionHeader[i].VirtualAddress <= (ULONG)rva)
      if ((sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) > (ULONG)rva)
      {
        *((PULONG)rva) -= sectionHeader[i].VirtualAddress;
        *((PULONG)rva) += sectionHeader[i].PointerToRawData;
        return (ULONG)rva < imageSize ? (ULONG)rva : (ULONG)KMOD_PE_ERROR_VALUE;
      }
  return (ULONG)KMOD_PE_ERROR_VALUE;
}

PVOID GetImageBase(PVOID imageBase, PVOID virtualBase)
{
  if ((ULONG64)virtualBase < (ULONG64)imageBase)
  {
    return NULL;
  }
  PVOID rva = (PVOID)((ULONG64)virtualBase - (ULONG64)imageBase);
  PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
  KM_LOG_INFO("e_magic %u\n", dosHeader->e_magic);
  KM_LOG_INFO("e_lfanew %p\n", (PULONG)dosHeader->e_lfanew);
  KM_LOG_INFO("e_cp %u\n", dosHeader->e_cp);
  if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
  {
    KM_LOG_ERROR("Invalid IMAGE_DOS_SIGNATURE\n");
    return NULL;
  }
  PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)imageBase + dosHeader->e_lfanew);
  if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
  {
    KM_LOG_ERROR("Invalid IMAGE_NT_SIGNATURE\n");
    return NULL;
  }
  PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
  USHORT section = RvaToSection(ntHeaders, rva);
  if (section == (USHORT)KMOD_PE_ERROR_VALUE)
  {
    KM_LOG_ERROR("Invalid section\n");
    return NULL;
  }
  return (PVOID)((PBYTE)imageBase + sectionHeader[section].VirtualAddress);
}
ULONG GetModuleExportOffset(PVOID imageBase, ULONG fileSize, PCCHAR exportName)
{
  PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
  if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
  {
    KM_LOG_ERROR("Invalid IMAGE_DOS_SIGNATURE\n");
    return (ULONG)KMOD_PE_ERROR_VALUE;
  }
  PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)imageBase + dosHeader->e_lfanew);
  if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
  {
    KM_LOG_ERROR("Invalid IMAGE_NT_SIGNATURE\n");
    return (ULONG)KMOD_PE_ERROR_VALUE;
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
  ULONG exportDirOffset = RvaToOffset(ntHeaders, &exportDirRva, fileSize);
  if (exportDirOffset == (ULONG)KMOD_PE_ERROR_VALUE)
  {
    KM_LOG_ERROR("Invalid export directory\n");
    return (ULONG)KMOD_PE_ERROR_VALUE;
  }
  PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)imageBase + exportDirOffset);
  ULONG numOfNames = exportDir->NumberOfNames;
  ULONG addressOfFunctionsOffset = RvaToOffset(ntHeaders, &exportDir->AddressOfFunctions, fileSize);
  ULONG addressOfNameOrdinalsOffset = RvaToOffset(ntHeaders, &exportDir->AddressOfNameOrdinals, fileSize);
  ULONG addressOfNamesOffset = RvaToOffset(ntHeaders, &exportDir->AddressOfNames, fileSize);
  if (addressOfFunctionsOffset == (ULONG)KMOD_PE_ERROR_VALUE || addressOfNameOrdinalsOffset == (ULONG)KMOD_PE_ERROR_VALUE || addressOfNamesOffset == (ULONG)KMOD_PE_ERROR_VALUE)
  {
    KM_LOG_ERROR("Invalid export directory content\n");
    return (ULONG)KMOD_PE_ERROR_VALUE;
  }
  PULONG addressOfFunctions = (PULONG)((PBYTE)imageBase + addressOfFunctionsOffset);
  PUSHORT addressOfNameOrdinals = (PUSHORT)((PBYTE)imageBase + addressOfNameOrdinalsOffset);
  PULONG addressOfNames = (PULONG)((PBYTE)imageBase + addressOfNamesOffset);
  ULONG exportOffset = (ULONG)KMOD_PE_ERROR_VALUE;
  for (ULONG i = 0; i < numOfNames; i++)
  {
    ULONG currentNameOffset = RvaToOffset(ntHeaders, &addressOfNames[i], fileSize);
    if (currentNameOffset == (ULONG)KMOD_PE_ERROR_VALUE)
    {
      continue;
    }
    PCCHAR currentName = (PCCHAR)((PBYTE)imageBase + currentNameOffset);
    ULONG currentFunctionRva = addressOfFunctions[addressOfNameOrdinals[i]];
    if (currentFunctionRva >= exportDirRva && currentFunctionRva < exportDirRva + exportDirSize)
    {
      continue;
    }
    if (strcmp(currentName, exportName) == 0)
    {
      exportOffset = RvaToOffset(ntHeaders, &currentFunctionRva, fileSize);
      break;
    }
  }
  if (exportOffset == (ULONG)KMOD_PE_ERROR_VALUE)
  {
    KM_LOG_ERROR("Export %s not found\n", exportName);
    return (ULONG)KMOD_PE_ERROR_VALUE;
  }
  return exportOffset;
}
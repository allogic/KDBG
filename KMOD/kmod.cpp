#include "global.h"
#include "ioctrl.h"

// TODO: fix wchar_t comparisons inhandled exception
// TODO: refactor ptr to stack objects

/*
* Global driver state.
*/

ULONG Pid = 0;

/*
* Stack frames.
*/

typedef struct _STACK_FRAME_X64
{
  ULONG64 AddrOffset;
  ULONG64 StackOffset;
  ULONG64 FrameOffset;
} STACK_FRAME_X64, * PSTACK_FRAME_X64;

/*
* Kernel utilities.
*/

template<typename FUNCTION>
FUNCTION GetSystemRoutine(PCWCHAR procName)
{
  static FUNCTION functionPointer = NULL;
  if (!functionPointer)
  {
    UNICODE_STRING functionName;
    RtlInitUnicodeString(&functionName, procName);
    functionPointer = (FUNCTION)MmGetSystemRoutineAddress(&functionName);
    if (!functionPointer)
    {
      KMOD_LOG_ERROR("MmGetSystemRoutineAddress\n");
      return NULL;
    }
  }
  return functionPointer;
}

/*
* Thread utilities.
*/

typedef NTSTATUS(*PSGETCONTEXTTHREAD)(
  PETHREAD Thread,
  PCONTEXT ThreadContext,
  KPROCESSOR_MODE Mode);
typedef NTSTATUS(*PSSETCONTEXTTHREAD)(
  PETHREAD Thread,
  PCONTEXT ThreadContext,
  KPROCESSOR_MODE Mode);

NTSTATUS PsGetContextThread(
  PETHREAD Thread,
  PCONTEXT ThreadContext,
  KPROCESSOR_MODE Mode)
{
  return GetSystemRoutine<PSGETCONTEXTTHREAD>(L"PsGetContextThread")(
    Thread,
    ThreadContext,
    Mode);
}
NTSTATUS PsSetContextThread(
  PETHREAD Thread,
  PCONTEXT ThreadContext,
  KPROCESSOR_MODE Mode)
{
  return GetSystemRoutine<PSSETCONTEXTTHREAD>(L"PsSetContextThread")(
    Thread,
    ThreadContext,
    Mode);
}

VOID DumpContext(PCONTEXT context)
{
  KMOD_LOG_INFO("Control flags\n");
  KMOD_LOG_INFO("ContextFlags: %u\n", context->ContextFlags);
  KMOD_LOG_INFO("MxCsr: %u\n", context->MxCsr);
  KMOD_LOG_INFO("\n");
  KMOD_LOG_INFO("Segment registers and processor flags\n");
  KMOD_LOG_INFO("SegCs: %u\n", context->SegCs);
  KMOD_LOG_INFO("SegDs: %u\n", context->SegDs);
  KMOD_LOG_INFO("SegEs: %u\n", context->SegEs);
  KMOD_LOG_INFO("SegFs: %u\n", context->SegFs);
  KMOD_LOG_INFO("SegGs: %u\n", context->SegGs);
  KMOD_LOG_INFO("SegSs: %u\n", context->SegSs);
  KMOD_LOG_INFO("EFlags: %u\n", context->EFlags);
  KMOD_LOG_INFO("\n");
  KMOD_LOG_INFO("Debug registers\n");
  KMOD_LOG_INFO("Dr0: %llu\n", context->Dr0);
  KMOD_LOG_INFO("Dr1: %llu\n", context->Dr1);
  KMOD_LOG_INFO("Dr2: %llu\n", context->Dr2);
  KMOD_LOG_INFO("Dr3: %llu\n", context->Dr3);
  KMOD_LOG_INFO("Dr6: %llu\n", context->Dr6);
  KMOD_LOG_INFO("Dr7: %llu\n", context->Dr7);
  KMOD_LOG_INFO("\n");
  KMOD_LOG_INFO("Integer registers\n");
  KMOD_LOG_INFO("Rax: %llu\n", context->Rax);
  KMOD_LOG_INFO("Rcx: %llu\n", context->Rcx);
  KMOD_LOG_INFO("Rdx: %llu\n", context->Rdx);
  KMOD_LOG_INFO("Rbx: %llu\n", context->Rbx);
  KMOD_LOG_INFO("Rsp: %llu\n", context->Rsp);
  KMOD_LOG_INFO("Rbp: %llu\n", context->Rbp);
  KMOD_LOG_INFO("Rsi: %llu\n", context->Rsi);
  KMOD_LOG_INFO("Rdi: %llu\n", context->Rdi);
  KMOD_LOG_INFO("R8: %llu\n", context->R8);
  KMOD_LOG_INFO("R9: %llu\n", context->R9);
  KMOD_LOG_INFO("R10: %llu\n", context->R10);
  KMOD_LOG_INFO("R11: %llu\n", context->R11);
  KMOD_LOG_INFO("R12: %llu\n", context->R12);
  KMOD_LOG_INFO("R13: %llu\n", context->R13);
  KMOD_LOG_INFO("R14: %llu\n", context->R14);
  KMOD_LOG_INFO("R15: %llu\n", context->R15);
  KMOD_LOG_INFO("\n");
  KMOD_LOG_INFO("Program counter\n");
  KMOD_LOG_INFO("Rip: %llu\n", context->Rip);
  KMOD_LOG_INFO("\n");
  KMOD_LOG_INFO("Special debug control registers\n");
  KMOD_LOG_INFO("DebugControl: %llu\n", context->DebugControl);
  KMOD_LOG_INFO("LastBranchToRip: %llu\n", context->LastBranchToRip);
  KMOD_LOG_INFO("LastBranchFromRip: %llu\n", context->LastBranchFromRip);
  KMOD_LOG_INFO("LastExceptionToRip: %llu\n", context->LastExceptionToRip);
  KMOD_LOG_INFO("LastExceptionFromRip: %llu\n", context->LastExceptionFromRip);
  KMOD_LOG_INFO("\n");
}

/*
* PE utilities.
*/

#define PE_ERROR_VALUE (PVOID)-1

typedef PPEB(*PSGETPROCESSPEB)(
  PEPROCESS Process);

PPEB PsGetProcessPeb(
  PEPROCESS process)
{
  return GetSystemRoutine<PSGETPROCESSPEB>(L"PsGetProcessPeb")(
    process);
}

typedef struct _PEB_LDR_DATA
{
  ULONG Length;
  BOOLEAN Initialized;
  PVOID SsHandler;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
  PVOID EntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
typedef struct _LDR_DATA_TABLE_ENTRY
{
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  CHAR Reserved0[0x10];
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
typedef struct _PEB64 {
  CHAR Reserved[0x10];
  PVOID ImageBaseAddress;
  PPEB_LDR_DATA Ldr;
} PEB64, * PPEB64;

USHORT RvaToSection(PIMAGE_NT_HEADERS ntHeaders, PVOID rva)
{
  PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
  USHORT numSections = ntHeaders->FileHeader.NumberOfSections;
  for (USHORT i = 0; i < numSections; ++i)
    if (sectionHeader[i].VirtualAddress <= (ULONG64)rva)
      if ((sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) > (ULONG64)rva)
        return i;
  return (USHORT)PE_ERROR_VALUE;
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
        return (ULONG)rva < imageSize ? (ULONG)rva : (ULONG)PE_ERROR_VALUE;
      }
  return (ULONG)PE_ERROR_VALUE;
}
PVOID GetVirtualBase(PVOID imageBase, PVOID virtualBase)
{
  if ((ULONG64)virtualBase < (ULONG64)imageBase)
  {
    return NULL;
  }
  PVOID rva = (PVOID)((ULONG64)virtualBase - (ULONG64)imageBase);
  PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
  KMOD_LOG_INFO("e_magic %u\n", dosHeader->e_magic);
  KMOD_LOG_INFO("e_lfanew %p\n", (PULONG)dosHeader->e_lfanew);
  KMOD_LOG_INFO("e_cp %u\n", dosHeader->e_cp);
  if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
  {
    KMOD_LOG_ERROR("Invalid IMAGE_DOS_SIGNATURE\n");
    return NULL;
  }
  PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)imageBase + dosHeader->e_lfanew);
  if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
  {
    KMOD_LOG_ERROR("Invalid IMAGE_NT_SIGNATURE\n");
    return NULL;
  }
  PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
  USHORT section = RvaToSection(ntHeaders, rva);
  if (section == (USHORT)PE_ERROR_VALUE)
  {
    KMOD_LOG_ERROR("Invalid section\n");
    return NULL;
  }
  return (PVOID)((PBYTE)imageBase + sectionHeader[section].VirtualAddress);
}

ULONG GetModuleExportOffset(PVOID imageBase, ULONG fileSize, PCCHAR exportName)
{
  PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
  if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
  {
    KMOD_LOG_ERROR("Invalid IMAGE_DOS_SIGNATURE\n");
    return (ULONG)PE_ERROR_VALUE;
  }
  PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)imageBase + dosHeader->e_lfanew);
  if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
  {
    KMOD_LOG_ERROR("Invalid IMAGE_NT_SIGNATURE\n");
    return (ULONG)PE_ERROR_VALUE;
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
  if (exportDirOffset == (ULONG)PE_ERROR_VALUE)
  {
    KMOD_LOG_ERROR("Invalid export directory\n");
    return (ULONG)PE_ERROR_VALUE;
  }
  PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)imageBase + exportDirOffset);
  ULONG numOfNames = exportDir->NumberOfNames;
  ULONG addressOfFunctionsOffset = RvaToOffset(ntHeaders, &exportDir->AddressOfFunctions, fileSize);
  ULONG addressOfNameOrdinalsOffset = RvaToOffset(ntHeaders, &exportDir->AddressOfNameOrdinals, fileSize);
  ULONG addressOfNamesOffset = RvaToOffset(ntHeaders, &exportDir->AddressOfNames, fileSize);
  if (addressOfFunctionsOffset == (ULONG)PE_ERROR_VALUE || addressOfNameOrdinalsOffset == (ULONG)PE_ERROR_VALUE || addressOfNamesOffset == (ULONG)PE_ERROR_VALUE)
  {
    KMOD_LOG_ERROR("Invalid export directory content\n");
    return (ULONG)PE_ERROR_VALUE;
  }
  PULONG addressOfFunctions = (PULONG)((PBYTE)imageBase + addressOfFunctionsOffset);
  PUSHORT addressOfNameOrdinals = (PUSHORT)((PBYTE)imageBase + addressOfNameOrdinalsOffset);
  PULONG addressOfNames = (PULONG)((PBYTE)imageBase + addressOfNamesOffset);
  ULONG exportOffset = (ULONG)PE_ERROR_VALUE;
  for (ULONG i = 0; i < numOfNames; i++)
  {
    ULONG currentNameOffset = RvaToOffset(ntHeaders, &addressOfNames[i], fileSize);
    if (currentNameOffset == (ULONG)PE_ERROR_VALUE)
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
  if (exportOffset == (ULONG)PE_ERROR_VALUE)
  {
    KMOD_LOG_ERROR("Export %s not found\n", exportName);
    return (ULONG)PE_ERROR_VALUE;
  }
  return exportOffset;
}
VOID DumpModuleExports(PVOID imageBase, ULONG fileSize)
{
  PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
  if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
  {
    KMOD_LOG_ERROR("Invalid IMAGE_DOS_SIGNATURE\n");
  }
  PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)imageBase + dosHeader->e_lfanew);
  if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
  {
    KMOD_LOG_ERROR("Invalid IMAGE_NT_SIGNATURE\n");
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
  if (exportDirOffset == (ULONG)PE_ERROR_VALUE)
  {
    KMOD_LOG_ERROR("Invalid export directory\n");
  }
  PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)imageBase + exportDirOffset);
  ULONG numOfNames = exportDir->NumberOfNames;
  ULONG addressOfFunctionsOffset = RvaToOffset(ntHeaders, &exportDir->AddressOfFunctions, fileSize);
  ULONG addressOfNameOrdinalsOffset = RvaToOffset(ntHeaders, &exportDir->AddressOfNameOrdinals, fileSize);
  ULONG addressOfNamesOffset = RvaToOffset(ntHeaders, &exportDir->AddressOfNames, fileSize);
  if (addressOfFunctionsOffset == (ULONG)PE_ERROR_VALUE || addressOfNameOrdinalsOffset == (ULONG)PE_ERROR_VALUE || addressOfNamesOffset == (ULONG)PE_ERROR_VALUE)
  {
    KMOD_LOG_ERROR("Invalid export directory content\n");
  }
  PULONG addressOfFunctions = (PULONG)((PBYTE)imageBase + addressOfFunctionsOffset);
  PUSHORT addressOfNameOrdinals = (PUSHORT)((PBYTE)imageBase + addressOfNameOrdinalsOffset);
  PULONG addressOfNames = (PULONG)((PBYTE)imageBase + addressOfNamesOffset);
  ULONG exportOffset = (ULONG)PE_ERROR_VALUE;
  KMOD_LOG_INFO("Exports:\n");
  for (ULONG i = 0; i < numOfNames; i++)
  {
    ULONG currentNameOffset = RvaToOffset(ntHeaders, &addressOfNames[i], fileSize);
    if (currentNameOffset == (ULONG)PE_ERROR_VALUE)
    {
      continue;
    }
    PCCHAR currentName = (PCCHAR)((PBYTE)imageBase + currentNameOffset);
    ULONG currentFunctionRva = addressOfFunctions[addressOfNameOrdinals[i]];
    if (currentFunctionRva >= exportDirRva && currentFunctionRva < exportDirRva + exportDirSize)
    {
      continue;
    }
    exportOffset = RvaToOffset(ntHeaders, &currentFunctionRva, fileSize);
    KMOD_LOG_INFO("\t%X %s\n", exportOffset, currentName);
  }
}

/*
* Process utilities relative to kernel space.
*/

NTSTATUS GetProcessModules(ULONG pid, SIZE_T size, SIZE_T& count, PVOID& buffer)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  PEPROCESS process = NULL;
  KAPC_STATE apc;
  status = PsLookupProcessByProcessId((HANDLE)pid, &process);
  if (NT_SUCCESS(status))
  {
    status = STATUS_UNSUCCESSFUL;
    KeStackAttachProcess(process, &apc);
    __try
    {
      PPEB64 peb = (PPEB64)PsGetProcessPeb(process);
      if (peb)
      {
        PVOID imageBase = peb->ImageBaseAddress;
        PLDR_DATA_TABLE_ENTRY modules = CONTAINING_RECORD(peb->Ldr->InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);;
        PLDR_DATA_TABLE_ENTRY module = NULL;
        PLIST_ENTRY moduleHead = modules->InMemoryOrderLinks.Flink;
        PLIST_ENTRY moduleEntry = moduleHead->Flink;
        while (moduleEntry != moduleHead)
        {
          module = CONTAINING_RECORD(moduleEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
          if (module && module->DllBase)
          {
            KMOD_LOG_INFO("Copy from %p to %p\n", module->DllBase, &((PMODULE)buffer)[count].Base);
            //((PMODULE)buffer)[count].Base = 666; //(ULONG64)module->DllBase;
            //wcscpy(((PMODULE)buffer)[size++].Name, module->BaseDllName.Buffer);
            //((PMODULE)buffer)[size++].Size = module->SizeOfImage;
          }
          moduleEntry = moduleEntry->Flink;
          count++;
          if (count >= size)
          {
            break;
          }
        }
        status = STATUS_SUCCESS;
      }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
      KMOD_LOG_ERROR("Something went wrong!\n");
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(process);
  }
  return status;
}
NTSTATUS GetProcessModuleBase(ULONG pid, PWCHAR name, PVOID& base)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  PEPROCESS process = NULL;
  KAPC_STATE apc;
  status = PsLookupProcessByProcessId((HANDLE)pid, &process);
  if (NT_SUCCESS(status))
  {
    status = STATUS_UNSUCCESSFUL;
    KeStackAttachProcess(process, &apc);
    __try
    {
      PPEB64 peb = (PPEB64)PsGetProcessPeb(process);
      if (peb)
      {
        PVOID imageBase = peb->ImageBaseAddress;
        PLDR_DATA_TABLE_ENTRY modules = CONTAINING_RECORD(peb->Ldr->InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);;
        PLDR_DATA_TABLE_ENTRY module = NULL;
        PLIST_ENTRY moduleHead = modules->InMemoryOrderLinks.Flink;
        PLIST_ENTRY moduleEntry = moduleHead->Flink;
        while (moduleEntry != moduleHead)
        {
          module = CONTAINING_RECORD(moduleEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
          if (module && module->DllBase)
          {
            //if (_wcsicmp(name, module->BaseDllName.Buffer) == 0)
            //{
            //  break;
            //}
            //if (RtlCompareUnicodeString(&requiredName, &currentName, TRUE) == 0)
            //{
            //  break;
            //}
          }
          moduleEntry = moduleEntry->Flink;
        }
        //module = CONTAINING_RECORD(moduleHead->Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        base = module->DllBase;
        status = STATUS_SUCCESS;
        KMOD_LOG_INFO("Selected module %wZ\n", &module->BaseDllName);
      }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
      KMOD_LOG_ERROR("Something went wrong!\n");
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(process);
  }
  return status;
}

NTSTATUS ReadVirtualProcessMemory(ULONG pid, PVOID base, SIZE_T size, PVOID buffer)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  PEPROCESS process = NULL;
  KAPC_STATE apc;
  status = PsLookupProcessByProcessId((HANDLE)pid, &process);
  if (NT_SUCCESS(status))
  {
    status = STATUS_UNSUCCESSFUL;
    PBYTE asyncBuffer = (PBYTE)RtlAllocateMemory(TRUE, size);
    if (asyncBuffer)
    {
      PMDL mdl = IoAllocateMdl(base, size, FALSE, FALSE, NULL);
      if (mdl)
      {
        KeStackAttachProcess(process, &apc);
        __try
        {
          MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
          PBYTE mappedBuffer = (PBYTE)MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, HighPagePriority);
          if (mappedBuffer)
          {
            status = MmProtectMdlSystemAddress(mdl, PAGE_READONLY);
            if (NT_SUCCESS(status))
            {
              status = STATUS_UNSUCCESSFUL;
              memcpy(asyncBuffer, mappedBuffer, size);
              KMOD_LOG_INFO("Copy successfull\n");
              status = STATUS_SUCCESS;
            }
            MmUnmapLockedPages(mappedBuffer, mdl);
          }
          MmUnlockPages(mdl);
          IoFreeMdl(mdl);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
          KMOD_LOG_ERROR("Something went wrong!\n");
          status = STATUS_UNHANDLED_EXCEPTION;
        }
        KeUnstackDetachProcess(&apc);
      }
      memcpy(buffer, asyncBuffer, size);
      RtlFreeMemory(asyncBuffer);
    }
    ObDereferenceObject(process);
  }
  return status;
}
NTSTATUS WriteVirtualProcessMemory(ULONG pid, PVOID base, SIZE_T size, PVOID buffer)
{
  return STATUS_UNSUCCESSFUL;
}

/*
* Scanning utilities.
*/

VOID ScanContext(HANDLE tid, SIZE_T iterations)
{
  //NTSTATUS status = STATUS_SUCCESS;
  //PETHREAD thread = NULL;
  //PCONTEXT context = NULL;
  //SIZE_T contextSize = sizeof(CONTEXT);
  //status = PsLookupThreadByThreadId(tid, &thread);
  //KMOD_LOG_ERROR_IF_NOT_SUCCESS(status, "PsLookupThreadByThreadId %X\n", status);
  //status = ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID*)&context, 0, &contextSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  //KMOD_LOG_ERROR_IF_NOT_SUCCESS(status, "ZwAllocateVirtualMemory %X\n", status);
  //RtlZeroMemory(context, contextSize);
  //LOG_INFO("Rax Rcx Rdx Rbx Rsp Rbp Rsi Rdi\n");
  //for (SIZE_T i = 0; i < iterations; ++i)
  //{
  //  context->ContextFlags = CONTEXT_ALL;
  //  status = PsGetContextThread(thread, context, UserMode);
  //  KMOD_LOG_ERROR_IF_NOT_SUCCESS(status, "PsGetContextThread %X\n", status);
  //  LOG_INFO("%llu %llu %llu %llu %llu %llu %llu %llu\n", context->Rax, context->Rcx, context->Rdx, context->Rbx, context->Rsp, context->Rbp, context->Rsi, context->Rdi);
  //}
  //if (context)
  //{
  //  ZwFreeVirtualMemory(ZwCurrentProcess(), (PVOID*)context, &contextSize, MEM_RELEASE);
  //}
  //ObDereferenceObject(thread);
}
VOID ScanStack(HANDLE pid, HANDLE tid, PWCHAR moduleName, SIZE_T iterations)
{
  //NTSTATUS status = STATUS_SUCCESS;
  //PEPROCESS process = NULL;
  //PETHREAD thread = NULL;
  //PCONTEXT context = NULL;
  //SIZE_T contextSize = sizeof(CONTEXT);
  //PLDR_DATA_TABLE_ENTRY modules = NULL;
  //PLDR_DATA_TABLE_ENTRY module = NULL;
  //PLIST_ENTRY moduleList = NULL;
  //PLIST_ENTRY moduleEntry = NULL;
  //STACK_FRAME_X64 stackFrame64;
  //PPEB64 peb = NULL;
  //KAPC_STATE apc;
  //// Get context infos
  //status = PsLookupProcessByProcessId(pid, &process);
  //KMOD_LOG_ERROR_IF_NOT_SUCCESS(status, "PsLookupProcessByProcessId %X", status);
  //status = PsLookupThreadByThreadId(tid, &thread);
  //KMOD_LOG_ERROR_IF_NOT_SUCCESS(status, "PsLookupThreadByThreadId %X\n", status);
  //status = ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID*)&context, 0, &contextSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  //KMOD_LOG_ERROR_IF_NOT_SUCCESS(status, "ZwAllocateVirtualMemory %X\n", status);
  //// Attach to process
  //KeStackAttachProcess(process, &apc);
  //// Get module base
  //peb = (PPEB64)PsGetProcessPeb(process);
  //KMOD_LOG_ERROR_IF_NOT(!peb, "PsGetProcessPeb\n");
  //modules = CONTAINING_RECORD(peb->Ldr->InLoadOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
  //moduleList = modules->InLoadOrderLinks.Flink;
  //moduleEntry = moduleList->Flink;
  //while (moduleEntry != moduleList)
  //{
  //  module = CONTAINING_RECORD(moduleEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
  //  if (wcscmp(moduleName, module->BaseDllName.Buffer) == 0)
  //  {
  //    break;
  //  }
  //  moduleEntry = moduleEntry->Flink;
  //}
  //KMOD_LOG_ERROR_IF_NOT(!module, "Module not found\n");
  //PVOID moduleBase = GetModuleBase((PBYTE)module->DllBase, *(PULONG)module->EntryPoint);
  //LOG_INFO("ModuleBase %p\n", moduleBase);
  ////ULONG moduleExportOffset = GetModuleExportOffset((PBYTE)module->DllBase, module->SizeOfImage, "");
  ////LOG_INFO("moduleExportOffset %p\n", moduleExportOffset);
  //// Dump exports
  //DumpModuleExports((PBYTE)module->DllBase, module->SizeOfImage);
  //// Dump stack frames
  //LOG_INFO("\n");
  //LOG_INFO("Stack Frames:\n");
  //for (SIZE_T i = 0; i < iterations; ++i)
  //{
  //  // Get context
  //  status = PsGetContextThread(thread, context, UserMode);
  //  KMOD_LOG_ERROR_IF_NOT_SUCCESS(status, "PsGetContextThread %X\n", status);
  //  // Get stack frame
  //  stackFrame64.AddrOffset = context->Rip; // Instruction ptr
  //  stackFrame64.StackOffset = context->Rsp; // Stack ptr
  //  stackFrame64.FrameOffset = context->Rbp; // Stack base ptr
  //  LOG_INFO("%4X %llu %llu %llu\n", i, stackFrame64.AddrOffset, stackFrame64.StackOffset, stackFrame64.FrameOffset);
  //}
  //// Detach from process
  //KeUnstackDetachProcess(&apc);
  //// Cleanup
  //if (context)
  //{
  //  ZwFreeVirtualMemory(ZwCurrentProcess(), (PVOID*)context, &contextSize, MEM_RELEASE);
  //}
  //ObDereferenceObject(thread);
  //ObDereferenceObject(process);
}

/*
* Communication device.
*/

#define KMOD_DEVICE_NAME L"\\Device\\KMOD"
#define KMOD_DEVICE_SYMBOL_NAME L"\\DosDevices\\KMOD"

PDEVICE_OBJECT Device = NULL;

VOID CreateDevice(PDRIVER_OBJECT driver, PDEVICE_OBJECT& device, PCWCHAR deviceName, PCWCHAR symbolicName)
{
  UNICODE_STRING deviceNameTmp;
  UNICODE_STRING symbolicNameTmp;
  RtlInitUnicodeString(&deviceNameTmp, deviceName);
  RtlInitUnicodeString(&symbolicNameTmp, symbolicName);
  IoCreateDevice(driver, 0, &deviceNameTmp, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, 0, &device);
  device->Flags |= (DO_DIRECT_IO | DO_BUFFERED_IO);
  device->Flags &= ~DO_DEVICE_INITIALIZING;
  IoCreateSymbolicLink(&symbolicNameTmp, &deviceNameTmp);
}
VOID DeleteDevice(PDEVICE_OBJECT device, PCWCHAR symbolicName)
{
  NTSTATUS status = STATUS_SUCCESS;
  UNICODE_STRING symbolicNameTmp;
  RtlInitUnicodeString(&symbolicNameTmp, symbolicName);
  status = IoDeleteSymbolicLink(&symbolicNameTmp);
  IoDeleteDevice(device);
}

/*
* Request/Response handlers.
*/

NTSTATUS HandleProcessAttachRequest(PREQ_PROCESS_ATTACH req)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  Pid = req->In.Pid;
  KMOD_LOG_INFO("Attached to process %u\n", Pid);
  status = STATUS_SUCCESS;
  return status;
}
NTSTATUS HandleProcessModulesRequest(PREQ_PROCESS_MODULES req)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  if (Pid)
  {
    status = GetProcessModules(Pid, req->In.Size, req->Out.Size, req->Out.Buffer);
  }
  return status;
}
NTSTATUS HandleMemoryReadRequest(PREQ_MEMORY_READ req)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  PVOID base = NULL;
  if (Pid)
  {
    status = GetProcessModuleBase(Pid, req->In.Name, base);
    if (NT_SUCCESS(status))
    {
      req->Out.Base = (ULONG64)base;
      status = ReadVirtualProcessMemory(Pid, (PVOID)((PBYTE)base + req->In.Offset), req->In.Size, req->Out.Buffer);
    }
  }
  return status;
}
NTSTATUS HandleMemoryWriteRequest(PREQ_MEMORY_WRITE req)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  PVOID base = NULL;
  if (Pid)
  {
    status = GetProcessModuleBase(Pid, req->In.Name, base);
    if (NT_SUCCESS(status))
    {
      req->Out.Base = (ULONG64)base;
      status = ReadVirtualProcessMemory(Pid, (PVOID)((PBYTE)base + req->In.Offset), req->In.Size, req->Out.Buffer);
    }
  }
  return status;
}

/*
* I/O callbacks.
*/

NTSTATUS OnIrpDflt(PDEVICE_OBJECT device, PIRP irp)
{
  UNREFERENCED_PARAMETER(device);
  irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
  irp->IoStatus.Information = 0;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return irp->IoStatus.Status;
}
NTSTATUS OnIrpCreate(PDEVICE_OBJECT device, PIRP irp)
{
  UNREFERENCED_PARAMETER(device);
  irp->IoStatus.Status = STATUS_SUCCESS;
  irp->IoStatus.Information = 0;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return irp->IoStatus.Status;
}
NTSTATUS OnIrpCtrl(PDEVICE_OBJECT device, PIRP irp)
{
  UNREFERENCED_PARAMETER(device);
  KMOD_LOG_INFO("========================================\n");
  PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
  switch (stack->Parameters.DeviceIoControl.IoControlCode)
  {
    case KMOD_REQ_PROCESS_ATTACH:
    {
      KMOD_LOG_INFO("Begin process attach\n");
      PREQ_PROCESS_ATTACH req = (PREQ_PROCESS_ATTACH)irp->AssociatedIrp.SystemBuffer;
      irp->IoStatus.Status = HandleProcessAttachRequest(req);
      irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? sizeof(PREQ_PROCESS_ATTACH) : 0;
      KMOD_LOG_INFO("End process attach\n");
      break;
    }
    case KMOD_REQ_PROCESS_MODULES:
    {
      KMOD_LOG_INFO("Begin process modules\n");
      PREQ_PROCESS_MODULES req = (PREQ_PROCESS_MODULES)irp->AssociatedIrp.SystemBuffer;
      irp->IoStatus.Status = HandleProcessModulesRequest(req);
      irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? sizeof(PREQ_PROCESS_MODULES) : 0;
      KMOD_LOG_INFO("End process modules\n");
      break;
    }
    case KMOD_REQ_MEMORY_READ:
    {
      KMOD_LOG_INFO("Begin memory read\n");
      PREQ_MEMORY_READ req = (PREQ_MEMORY_READ)irp->AssociatedIrp.SystemBuffer;
      irp->IoStatus.Status = HandleMemoryReadRequest(req);
      irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? sizeof(PREQ_MEMORY_READ) : 0;
      KMOD_LOG_INFO("End memory read\n");
      break;
    }
    case KMOD_REQ_MEMORY_WRITE:
    {
      KMOD_LOG_INFO("Begin memory write\n");
      PREQ_MEMORY_WRITE req = (PREQ_MEMORY_WRITE)irp->AssociatedIrp.SystemBuffer;
      irp->IoStatus.Status = HandleMemoryWriteRequest(req);
      irp->IoStatus.Information = NT_SUCCESS(irp->IoStatus.Status) ? sizeof(PREQ_MEMORY_WRITE) : 0;
      KMOD_LOG_INFO("End memory write\n");
      break;
    }
  }
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  KMOD_LOG_INFO("========================================\n");
  return irp->IoStatus.Status;
}
NTSTATUS OnIrpClose(PDEVICE_OBJECT device, PIRP irp)
{
  UNREFERENCED_PARAMETER(device);
  irp->IoStatus.Status = STATUS_SUCCESS;
  irp->IoStatus.Information = 0;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return irp->IoStatus.Status;
}

/*
* Entry point.
*/

VOID DriverUnload(PDRIVER_OBJECT driver)
{
  UNREFERENCED_PARAMETER(driver);
  NTSTATUS status = STATUS_SUCCESS;
  DeleteDevice(Device, KMOD_DEVICE_SYMBOL_NAME);
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING regPath)
{
  UNREFERENCED_PARAMETER(regPath);
  NTSTATUS status = STATUS_SUCCESS;
  driver->DriverUnload = DriverUnload;
  for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
    driver->MajorFunction[i] = OnIrpDflt;
  driver->MajorFunction[IRP_MJ_CREATE] = OnIrpCreate;
  driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OnIrpCtrl;
  driver->MajorFunction[IRP_MJ_CLOSE] = OnIrpClose;
  CreateDevice(driver, Device, KMOD_DEVICE_NAME, KMOD_DEVICE_SYMBOL_NAME);
  return status;
}
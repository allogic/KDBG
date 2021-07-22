#ifndef _PE_H
#define _PE_H

#include "global.h"
#include "krnl.h"

/*
* PE utilities.
*/

#define KMOD_PE_ERROR_VALUE (PVOID)-1

typedef PPEB(*PSGETPROCESSPEB)(
  PEPROCESS Process);

PPEB PsGetProcessPeb(
  PEPROCESS process);

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

USHORT RvaToSection(PIMAGE_NT_HEADERS ntHeaders, PVOID rva);
ULONG RvaToOffset(PIMAGE_NT_HEADERS ntHeaders, PVOID rva, ULONG imageSize);

PVOID GetImageBase(PVOID imageBase, PVOID virtualBase);
ULONG GetModuleExportOffset(PVOID imageBase, ULONG fileSize, PCCHAR exportName);

#endif
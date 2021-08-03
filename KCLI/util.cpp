#include "util.h"

ULONG
GetProcessIdFromNameW(
  PCWCHAR processName)
{
  PROCESSENTRY32 pe;
  pe.dwSize = sizeof(PROCESSENTRY32);
  PVOID snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (!Process32First(snapshot, &pe))
  {
    CloseHandle(snapshot);
    return 0;
  }
  do
  {
    if (_wcsicmp(processName, pe.szExeFile) == 0)
    {
      ULONG pid = pe.th32ProcessID;
      CloseHandle(snapshot);
      return pid;
    }
  } while (Process32Next(snapshot, &pe));
  CloseHandle(snapshot);
  return 0;
}

VOID
Utf16ToUtf8(
  PWCHAR utf16,
  PCHAR utf8)
{
  wcstombs_s(NULL, utf8, wcslen(utf16) + 1, utf16, _TRUNCATE);
}

VOID
Utf8ToUtf16(
  PCHAR utf8,
  PWCHAR utf16)
{
  mbstowcs_s(NULL, utf16, strlen(utf8) + 1, utf8, _TRUNCATE);
}

VOID
HexToBytesW(
  PBYTE bytes,
  PWCHAR argv)
{
  WCHAR byte[2];
  for (ULONG i = 0, j = 0; i < wcslen(argv) - 1; i += 2, j++)
  {
    wcsncpy(byte, argv + i, 2);
    bytes[j] = (BYTE)wcstoul(byte, NULL, 16);
  }
}
#include "global.h"
#include "ioctrl.h"

using namespace std;

wstring Utf8ToUtf16(string const& utf8Str)
{
  return wstring_convert<codecvt_utf8_utf16<wchar_t>>{}.from_bytes(utf8Str);
}
string Utf16ToUtf8(wstring const& utf16Str)
{
  return wstring_convert<codecvt_utf8_utf16<wchar_t>>{}.to_bytes(utf16Str);
}

ULONG GetProcessIdFromName(PCWCHAR processName)
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

HANDLE Device = NULL;

INT
wmain(
  INT argc,
  PWCHAR argv[])
{
  Device = CreateFileA("\\\\.\\KMOD", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);

  // Test read memory process
  {
    READ_MEMORY_PROCESS request;
    request.Pid = GetProcessIdFromName(L"taskmgr.exe");
    wcscpy_s(request.ImageName, L"taskmgr.exe");
    request.Offset = 0;
    request.Size = 32;
    
    CHAR response[32];
    memset(response, 0, sizeof(response));

    if (DeviceIoControl(Device, KM_READ_MEMORY_PROCESS, &request, sizeof(request), &response, sizeof(response), 0, 0))
    {
      KC_LOG_INFO("Read process\n");
      for (SIZE_T i = 0; i < sizeof(response); ++i)
      {
        KC_LOG_INFO("%u\n", response[i]);
      }
    }
  }
  // Test read memory kernel
  {
    READ_MEMORY_KERNEL request;
    strcpy_s(request.ImageName, "ntoskrnl.exe");
    request.Offset = 0;
    request.Size = 32;

    CHAR response[32];
    memset(response, 0, sizeof(response));

    if (DeviceIoControl(Device, KM_READ_MEMORY_KERNEL, &request, sizeof(request), &response, sizeof(response), 0, 0))
    {
      KC_LOG_INFO("Read kernel\n");
      for (SIZE_T i = 0; i < sizeof(response); ++i)
      {
        KC_LOG_INFO("%u\n", response[i]);
      }
    }
  }
  return 0;
}
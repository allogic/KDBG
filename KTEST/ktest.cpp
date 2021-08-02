#include "global.h"
#include "ioctrl.h"
#include "common.h"

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
  // Test write memory process
  {
    WRITE_MEMORY_PROCESS request;
    request.Pid = GetProcessIdFromName(L"taskmgr.exe");
    wcscpy_s(request.ImageName, L"taskmgr.exe");
    request.Offset = 0;
    request.Size = 1;
    memset(request.Bytes, 90, sizeof(request.Bytes));

    if (DeviceIoControl(Device, KM_WRITE_MEMORY_PROCESS, &request, sizeof(request), 0, 0, 0, 0))
    {
      KC_LOG_INFO("Write memory process\n");
      KC_LOG_INFO("Test passed\n");
    }
  }
  // Test write memory kernel
  {
    WRITE_MEMORY_KERNEL request;
    wcscpy_s(request.ImageName, L"ntoskrnl.exe");
    request.Offset = 0;
    request.Size = 1;
    memset(request.Bytes, 90, sizeof(request.Bytes));

    if (DeviceIoControl(Device, KM_WRITE_MEMORY_KERNEL, &request, sizeof(request), 0, 0, 0, 0))
    {
      KC_LOG_INFO("Write memory kernel\n");
      KC_LOG_INFO("Test passed\n");
    }
  }
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
      KC_LOG_INFO("Read memory process\n");
      for (SIZE_T i = 0; i < request.Size; ++i)
      {
        KC_LOG_INFO("%02X\n", response[i]);
      }
      KC_LOG_INFO("Test passed\n");
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
      KC_LOG_INFO("Read memory kernel\n");
      for (SIZE_T i = 0; i < request.Size; ++i)
      {
        KC_LOG_INFO("%02X\n", response[i]);
      }
      KC_LOG_INFO("Test passed\n");
    }
  }
  // Test read modules process
  {
    READ_MODULES_PROCESS request;
    request.Pid = GetProcessIdFromName(L"taskmgr.exe");
    request.Size = 1;

    KM_MODULE_PROCESS response[1];
    memset(response, 0, sizeof(response));

    if (DeviceIoControl(Device, KM_READ_MODULES_PROCESS, &request, sizeof(request), &response, sizeof(response), 0, 0))
    {
      KC_LOG_INFO("Read modules process\n");
      for (SIZE_T i = 0; i < request.Size; ++i)
      {
        KC_LOG_INFO("%ls\n", response[i].Name);
        KC_LOG_INFO("%p\n", (PVOID)response[i].Base);
        KC_LOG_INFO("%lu\n", response[i].Size);
      }
      KC_LOG_INFO("Test passed\n");
    }
  }
  // Test read modules kernel
  {
    READ_MODULES_KERNEL request;
    request.Size = 1;

    KM_MODULE_KERNEL response[1];
    memset(response, 0, sizeof(response));

    if (DeviceIoControl(Device, KM_READ_MODULES_KERNEL, &request, sizeof(request), &response, sizeof(response), 0, 0))
    {
      KC_LOG_INFO("Read modules kernel\n");
      for (SIZE_T i = 0; i < request.Size; ++i)
      {
        KC_LOG_INFO("%s\n", response[i].Name);
        KC_LOG_INFO("%p\n", (PVOID)response[i].Base);
        KC_LOG_INFO("%lu\n", response[i].Size);
      }
      KC_LOG_INFO("Test passed\n");
    }
  }
  // Test read threads process
  {
    READ_THREADS_PROCESS request;
    request.Pid = GetProcessIdFromName(L"taskmgr.exe");
    request.Size = 1;

    KM_THREAD_PROCESS response[1];
    memset(response, 0, sizeof(response));

    if (DeviceIoControl(Device, KM_READ_THREADS_PROCESS, &request, sizeof(request), &response, sizeof(response), 0, 0))
    {
      KC_LOG_INFO("Read threads process\n");
      for (SIZE_T i = 0; i < request.Size; ++i)
      {
        KC_LOG_INFO("%u\n", response[i].Tid);
        KC_LOG_INFO("%u\n", response[i].Pid);
      }
      KC_LOG_INFO("Test passed\n");
    }
  }
  // Test trace context start
  {
    TRACE_CONTEXT_START request;
    request.Address = 0;

    ULONG response = 0;

    if (DeviceIoControl(Device, KM_TRACE_CONTEXT_START, &request, sizeof(request), &response, sizeof(response), 0, 0))
    {
      KC_LOG_INFO("Start trace context\n");
      KC_LOG_INFO("Trace started with id %u\n", response);
      KC_LOG_INFO("Test passed\n");
    }
  }
  // Test trace context stop
  {
    TRACE_CONTEXT_STOP request;
    request.Id = 0;

    ULONG64 response[64];
    memset(response, 0, sizeof(response));

    if (DeviceIoControl(Device, KM_TRACE_CONTEXT_STOP, &request, sizeof(request), &response, sizeof(response), 0, 0))
    {
      KC_LOG_INFO("Stop trace context\n");
      for (ULONG i = 0; i < 64; ++i)
      {
        KC_LOG_INFO("Found opcode %llu\n", response[i]);
      }
      KC_LOG_INFO("Test passed\n");
    }
  }
  // Test debug breakpoint set
  {
    DEBUG_BREAKPOINT_SET request;
    request.Base = 0;
    request.Type = DEBUG_BREAKPOINT_SET::Software;

    if (DeviceIoControl(Device, KM_DEBUG_BREAKPOINT_SET, &request, sizeof(request), 0, 0, 0, 0))
    {
      KC_LOG_INFO("Debug breakpoint set\n");
      KC_LOG_INFO("Test passed\n");
    }
  }
  // Test debug breakpoint rem
  {
    DEBUG_BREAKPOINT_REM request;
    request.Base = 0;

    if (DeviceIoControl(Device, KM_DEBUG_BREAKPOINT_REM, &request, sizeof(request), 0, 0, 0, 0))
    {
      KC_LOG_INFO("Debug breakpoint rem\n");
      KC_LOG_INFO("Test passed\n");
    }
  }
  return 0;
}
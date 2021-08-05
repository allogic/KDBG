#include "global.h"
#include "common.h"
#include "ioctrl.h"
#include "util.h"
#include "disasm.h"

/*
* I/O communication device.
*/

#define KC_DEVICE_NAME "\\\\.\\KMOD"

HANDLE Device = NULL;

/*
* Entry point.
*/

INT
wmain(
  INT argc,
  PWCHAR argv[])
{
  Device = CreateFileA(KC_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
  if (Device != NULL)
  {
    // Write API
    if (_wcsicmp(L"/WriteMemoryProcess", argv[1]) == 0)
    {
      WRITE_MEMORY_PROCESS request = {};
      request.Pid = GetProcessIdFromNameW(argv[2]);
      wcscpy_s(request.ImageName, argv[3]);
      request.Offset = wcstoul(argv[4], NULL, 16);
      request.Size = wcstoul(argv[5], NULL, 10);
      HexToBytesW(request.Bytes, argv[6]);

      DeviceIoControl(Device, KM_WRITE_MEMORY_PROCESS, &request, sizeof(request), 0, 0, 0, 0);
      printf("\n");
    }
    if (_wcsicmp(L"/WriteMemoryKernel", argv[1]) == 0)
    {
      WRITE_MEMORY_KERNEL request = {};
      Utf16ToUtf8(argv[2], request.ImageName);
      request.Offset = wcstoul(argv[3], NULL, 16);
      request.Size = wcstoul(argv[4], NULL, 10);
      HexToBytesW(request.Bytes, argv[5]);

      DeviceIoControl(Device, KM_WRITE_MEMORY_KERNEL, &request, sizeof(request), 0, 0, 0, 0);
      printf("\n");
    }
    // Read API
    if (_wcsicmp(L"/ReadMemoryProcess", argv[1]) == 0)
    {
      READ_MEMORY_PROCESS request = {};
      request.Pid = GetProcessIdFromNameW(argv[2]);
      wcscpy_s(request.ImageName, argv[3]);
      request.Offset = wcstoul(argv[4], NULL, 16);
      request.Size = wcstoul(argv[5], NULL, 10);

      PBYTE response = (PBYTE)malloc(sizeof(BYTE) * request.Size);

      if (DeviceIoControl(Device, KM_READ_MEMORY_PROCESS, &request, sizeof(request), response, sizeof(BYTE) * request.Size, 0, 0))
      {
        printf("\n");
        printf("0x%08X ", request.Offset);
        for (ULONG i = 0; i < request.Size; i++)
        {
          printf("%02X ", response[i]);
          if (i != 0 && (i + 1) < request.Size && (i + 1) % 32 == 0)
            printf("\n0x%08X ", request.Offset + (ULONG)i);
        }
        printf("\n\n");
        DisassembleBytes(response, request.Size, request.Offset);
        printf("\n");
      }

      free(response);
    }
    if (_wcsicmp(L"/ReadMemoryKernel", argv[1]) == 0)
    {
      READ_MEMORY_KERNEL request = {};
      Utf16ToUtf8(argv[2], request.ImageName);
      request.Offset = wcstoul(argv[3], NULL, 16);
      request.Size = wcstoul(argv[4], NULL, 10);

      PBYTE response = (PBYTE)malloc(sizeof(BYTE) * request.Size);

      if (DeviceIoControl(Device, KM_READ_MEMORY_KERNEL, &request, sizeof(request), response, sizeof(BYTE) * request.Size, 0, 0))
      {
        printf("\n");
        printf("0x%08X ", request.Offset);
        for (ULONG i = 0; i < request.Size; i++)
        {
          printf("%02X ", response[i]);
          if (i != 0 && (i + 1) < request.Size && (i + 1) % 32 == 0)
            printf("\n0x%08X ", request.Offset + (ULONG)i);
        }
        printf("\n\n");
        DisassembleBytes(response, request.Size, request.Offset);
        printf("\n");
      }

      free(response);
    }
    if (_wcsicmp(L"/ReadModulesProcess", argv[1]) == 0)
    {
      READ_MODULES_PROCESS request = {};
      request.Pid = GetProcessIdFromNameW(argv[2]);
      request.Size = wcstoul(argv[3], NULL, 10);

      PKM_MODULE_PROCESS response = (PKM_MODULE_PROCESS)malloc(sizeof(KM_MODULE_PROCESS) * request.Size);

      if (DeviceIoControl(Device, KM_READ_MODULES_PROCESS, &request, sizeof(request), response, sizeof(KM_MODULE_PROCESS) * request.Size, 0, 0))
      {
        printf("\n");
        printf("  Start            End                    Size Name\n");
        printf("----------------------------------------------------------------\n");
        for (ULONG i = 0; i < request.Size; ++i)
        {
          printf("  %16p %16p %10lu %ls\n",
            (PVOID)response[i].Base,
            (PVOID)(response[i].Base + response[i].Size),
            response[i].Size,
            response[i].Name);
        }
        printf("\n");
      }

      free(response);
    }
    if (_wcsicmp(L"/ReadModulesKernel", argv[1]) == 0)
    {
      READ_MODULES_KERNEL request = {};
      request.Size = wcstoul(argv[2], NULL, 10);

      PKM_MODULE_KERNEL response = (PKM_MODULE_KERNEL)malloc(sizeof(KM_MODULE_KERNEL) * request.Size);

      if (DeviceIoControl(Device, KM_READ_MODULES_KERNEL, &request, sizeof(request), response, sizeof(KM_MODULE_KERNEL) * request.Size, 0, 0))
      {
        printf("\n");
        printf("  Start            End                    Size Name\n");
        printf("----------------------------------------------------------------\n");
        for (ULONG i = 0; i < request.Size; ++i)
        {
          printf("  %16p %16p %10lu %s\n",
            (PVOID)response[i].Base,
            (PVOID)(response[i].Base + response[i].Size),
            response[i].Size,
            response[i].Name);
        }
        printf("\n");
      }

      free(response);
    }
    if (_wcsicmp(L"/ReadThreadsProcess", argv[1]) == 0)
    {
      READ_THREADS_PROCESS request = {};
      request.Pid = GetProcessIdFromNameW(argv[2]);
      request.Size = wcstoul(argv[3], NULL, 10);

      PKM_THREAD_PROCESS response = (PKM_THREAD_PROCESS)malloc(sizeof(KM_THREAD_PROCESS) * request.Size);

      if (DeviceIoControl(Device, KM_READ_THREADS_PROCESS, &request, sizeof(request), response, sizeof(KM_THREAD_PROCESS) * request.Size, 0, 0))
      {
        printf("\n");
        printf("  Pid Tid\n");
        printf("----------------------------------------------------------------\n");
        for (ULONG i = 0; i < request.Size; ++i)
        {
          printf("  %lu %lu\n",
            response[i].Pid,
            response[i].Tid);
        }
        printf("\n");
      }

      free(response);
    }
    if (_wcsicmp(L"/ReadScanResults", argv[1]) == 0)
    {
      READ_SCAN_RESULTS request = {};

      if (DeviceIoControl(Device, KM_READ_SCAN_RESULTS, &request, sizeof(request), 0, 0, 0, 0))
      {

      }
    }
    // Trace API
    if (_wcsicmp(L"/TraceContextStart", argv[1]) == 0)
    {
      TRACE_CONTEXT_START request = {};
      request.Tid = wcstoul(argv[2], NULL, 10);
      request.Address = wcstoul(argv[3], NULL, 16);

      ULONG response = 0;

      if (DeviceIoControl(Device, KM_TRACE_CONTEXT_START, &request, sizeof(request), &response, sizeof(response), 0, 0))
      {
        printf("\n");
        printf("Trace %lu started\n", response);
        printf("\n");
      }
    }
    if (_wcsicmp(L"/TraceContextStop", argv[1]) == 0)
    {
      TRACE_CONTEXT_STOP request = {};
      request.Id = wcstoul(argv[2], NULL, 10);

      ULONG64 response[64] = {};

      if (DeviceIoControl(Device, KM_TRACE_CONTEXT_STOP, &request, sizeof(request), &response, sizeof(response), 0, 0))
      {
        printf("\n");
        printf("Trace %lu stopped\n", request.Id);
        printf("\n");
        for (ULONG i = 0; i < 64; ++i)
        {
          printf("%llu\n", response[i]);
        }
        printf("\n");
      }
    }
    // Debug API
    if (_wcsicmp(L"/DebugBreakpointSet", argv[1]) == 0)
    {
      DEBUG_BREAKPOINT_SET request = {};
      request.Base = wcstoul(argv[2], NULL, 16);
      request.Type = (DEBUG_BREAKPOINT_SET::TYPE)wcstoul(argv[3], NULL, 10);

      if (DeviceIoControl(Device, KM_DEBUG_BREAKPOINT_SET, &request, sizeof(request), 0, 0, 0, 0))
      {

      }
    }
    if (_wcsicmp(L"/DebugBreakpointRem", argv[1]) == 0)
    {
      DEBUG_BREAKPOINT_REM request = {};
      request.Base = wcstoul(argv[2], NULL, 16);

      if (DeviceIoControl(Device, KM_DEBUG_BREAKPOINT_REM, &request, sizeof(request), 0, 0, 0, 0))
      {

      }
    }
    // Scan API
    if (_wcsicmp(L"/ReadScanNew", argv[1]) == 0)
    {
      SCAN_NEW request = {};

      if (DeviceIoControl(Device, KM_SCAN_NEW, &request, sizeof(request), 0, 0, 0, 0))
      {

      }
    }
    if (_wcsicmp(L"/ReadScanUndo", argv[1]) == 0)
    {
      SCAN_UNDO request = {};

      if (DeviceIoControl(Device, KM_SCAN_UNDO, &request, sizeof(request), 0, 0, 0, 0))
      {

      }
    }
    if (_wcsicmp(L"/ReadScanInt", argv[1]) == 0)
    {
      SCAN_INT request = {};

      if (DeviceIoControl(Device, KM_SCAN_INT, &request, sizeof(request), 0, 0, 0, 0))
      {

      }
    }
    if (_wcsicmp(L"/ReadScanReal", argv[1]) == 0)
    {
      SCAN_REAL request = {};

      if (DeviceIoControl(Device, KM_SCAN_REAL, &request, sizeof(request), 0, 0, 0, 0))
      {

      }
    }
    if (_wcsicmp(L"/ReadScanBytes", argv[1]) == 0)
    {
      SCAN_BYTES request = {};

      if (DeviceIoControl(Device, KM_SCAN_BYTES, &request, sizeof(request), 0, 0, 0, 0))
      {

      }
    }
    if (_wcsicmp(L"/ReadScanFilterChanged", argv[1]) == 0)
    {
      SCAN_FILTER_CHANGED request = {};

      if (DeviceIoControl(Device, KM_SCAN_FILTER_CHANGED, &request, sizeof(request), 0, 0, 0, 0))
      {

      }
    }
    if (_wcsicmp(L"/ReadScanFilterUnchanged", argv[1]) == 0)
    {
      SCAN_FILTER_UNCHANGED request = {};

      if (DeviceIoControl(Device, KM_SCAN_FILTER_UNCHANGED, &request, sizeof(request), 0, 0, 0, 0))
      {

      }
    }
    if (_wcsicmp(L"/ReadScanFilterIncreased", argv[1]) == 0)
    {
      SCAN_FILTER_INCREASED request = {};

      if (DeviceIoControl(Device, KM_SCAN_FILTER_INCREASED, &request, sizeof(request), 0, 0, 0, 0))
      {

      }
    }
    if (_wcsicmp(L"/ReadScanFilterDecreased", argv[1]) == 0)
    {
      SCAN_FILTER_DECREASED request = {};

      if (DeviceIoControl(Device, KM_SCAN_FILTER_DECREASED, &request, sizeof(request), 0, 0, 0, 0))
      {

      }
    }
  }
  return 0;
}
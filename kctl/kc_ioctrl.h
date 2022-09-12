#ifndef KC_IOCTRL_H
#define KC_IOCTRL_H

#include <kc_core.h>

///////////////////////////////////////////////////////////
// Externals
///////////////////////////////////////////////////////////

extern HANDLE g_driverHandle;

///////////////////////////////////////////////////////////
// I/O control codes
///////////////////////////////////////////////////////////

#define IOCTRL_UPDATE_PROCESS_IMAGES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0100, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTRL_UPDATE_KERNEL_IMAGES  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0101, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IOCTRL_READ_PROCESS_IMAGES   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0200, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTRL_READ_KERNEL_IMAGES    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0201, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTRL_READ_PROCESS_MEMORY   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0202, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTRL_READ_KERNEL_MEMORY    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0203, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTRL_READ_SCAN_RESULTS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0204, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IOCTRL_WRITE_PROCESS_MEMORY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0300, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTRL_WRITE_KERNEL_MEMORY   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0301, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IOCTRL_SCAN_PROCESS_FIRST    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0400, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTRL_SCAN_PROCESS_NEXT     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0401, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

///////////////////////////////////////////////////////////
// I/O request data types
///////////////////////////////////////////////////////////

typedef enum _SCAN_TYPE
{
  SCAN_TYPE_BYTE8,
  SCAN_TYPE_BYTE16,
  SCAN_TYPE_BYTE32,
  SCAN_TYPE_BYTE64,
} SCAN_TYPE, * PSCAN_TYPE;

typedef struct _READ_PROCESS_MEMORY
{
  DWORD32 Pid;
  DWORD64 Base;
  DWORD32 Size;
} READ_PROCESS_MEMORY, * PREAD_PROCESS_MEMORY;
typedef struct _READ_KERNEL_MEMORY
{
  DWORD64 Base;
  DWORD32 Size;
} READ_KERNEL_MEMORY, * PREAD_KERNEL_MEMORY;

typedef struct _WRITE_PROCESS_MEMORY
{
  DWORD32 Pid;
  DWORD64 Base;
  DWORD32 Size;
  PVOID Buffer;
} WRITE_PROCESS_MEMORY, * PWRITE_PROCESS_MEMORY;
typedef struct _WRITE_KERNEL_MEMORY
{
  DWORD64 Base;
  DWORD32 Size;
  PVOID Buffer;
} WRITE_KERNEL_MEMORY, * PWRITE_KERNEL_MEMORY;

typedef struct _SCAN_PROCESS_FIRST
{
  DWORD32 Pid;
  DWORD64 Base;
  DWORD32 Size;
  PVOID Buffer;
  DWORD32 Type;
} SCAN_PROCESS_FIRST, * PSCAN_PROCESS_FIRST;
typedef struct _SCAN_PROCESS_NEXT
{
  DWORD32 Pid;
} SCAN_PROCESS_NEXT, * PSCAN_PROCESS_NEXT;

///////////////////////////////////////////////////////////
// I/O response data types
///////////////////////////////////////////////////////////

typedef struct _PROCESS_IMAGE
{
  DWORD64 Base;
  DWORD32 Size;
  WCHAR Name[260];
} PROCESS_IMAGE, * PPROCESS_IMAGE;
typedef struct _KERNEL_IMAGE
{
  DWORD64 Base;
  DWORD32 Size;
  CHAR Name[260];
} KERNEL_IMAGE, * PKERNEL_IMAGE;

///////////////////////////////////////////////////////////
// I/O utilities
///////////////////////////////////////////////////////////

namespace kdbg::ioctrl
{
  // Read images

  static void ReadProcessImages(DWORD32 pid, std::vector<PROCESS_IMAGE>& buffer)
  {
    DWORD32 count = 0;
    DeviceIoControl(g_driverHandle, IOCTRL_UPDATE_PROCESS_IMAGES, &pid, sizeof(DWORD32), &count, sizeof(DWORD32), nullptr, nullptr);
    buffer.clear();
    if (count > 0)
    {
      buffer.resize(count);
      DeviceIoControl(g_driverHandle, IOCTRL_READ_PROCESS_IMAGES, &count, sizeof(DWORD32), &buffer[0], sizeof(PROCESS_IMAGE) * count, nullptr, nullptr);
    }
  }

  static void ReadKernelImages(std::vector<KERNEL_IMAGE>& buffer)
  {
    DWORD32 count = 0;
    DeviceIoControl(g_driverHandle, IOCTRL_UPDATE_KERNEL_IMAGES, nullptr, 0, &count, sizeof(DWORD32), nullptr, nullptr);
    buffer.clear();
    if (count > 0)
    {
      buffer.resize(count);
      DeviceIoControl(g_driverHandle, IOCTRL_READ_KERNEL_IMAGES, &count, sizeof(DWORD32), &buffer[0], sizeof(KERNEL_IMAGE) * count, nullptr, nullptr);
    }
  }

  // Read process memory

  template<typename T>
  static T ReadProcessMemory(DWORD32 pid, DWORD64 base)
  {
    READ_PROCESS_MEMORY request{ pid, base, sizeof(T) };
    T value = {};
    DeviceIoControl(g_driverHandle, IOCTRL_READ_PROCESS_MEMORY, &request, sizeof(READ_PROCESS_MEMORY), &value, sizeof(T), nullptr, nullptr);
    return value;
  }

  template<typename T>
  static void ReadProcessMemory(DWORD32 pid, DWORD64 base, T* buffer, DWORD32 count)
  {
    READ_PROCESS_MEMORY request{ pid, base, sizeof(T) * count };
    DeviceIoControl(g_driverHandle, IOCTRL_READ_PROCESS_MEMORY, &request, sizeof(READ_PROCESS_MEMORY), buffer, sizeof(T) * count, nullptr, nullptr);
  }

  // Read kernel memory

  template<typename T>
  static T ReadKernelMemory(DWORD64 base)
  {
    T value = {};
    READ_KERNEL_MEMORY request{ base, sizeof(T) };
    DeviceIoControl(g_driverHandle, IOCTRL_READ_KERNEL_MEMORY, &request, sizeof(READ_KERNEL_MEMORY), &value, sizeof(T), nullptr, nullptr);
    return value;
  }

  template<typename T>
  static void ReadKernelMemory(DWORD64 base, T* buffer, DWORD32 count)
  {
    READ_KERNEL_MEMORY request{ base, sizeof(T) * count };
    DeviceIoControl(g_driverHandle, IOCTRL_READ_KERNEL_MEMORY, &request, sizeof(READ_KERNEL_MEMORY), buffer, sizeof(T) * count, nullptr, nullptr);
  }

  // Write process memory

  template<typename T>
  static void WriteProcessMemory(DWORD32 pid, DWORD64 base, T value)
  {
    WRITE_PROCESS_MEMORY request{ pid, base, sizeof(T), &value };
    DeviceIoControl(g_driverHandle, IOCTRL_WRITE_PROCESS_MEMORY, &request, sizeof(WRITE_PROCESS_MEMORY), nullptr, 0, nullptr, nullptr);
  }

  template<typename T>
  static void WriteProcessMemory(DWORD32 pid, DWORD64 base, T* buffer, DWORD32 count)
  {
    WRITE_PROCESS_MEMORY request{ pid, base, sizeof(T) * count, buffer };
    DeviceIoControl(g_driverHandle, IOCTRL_WRITE_PROCESS_MEMORY, &request, sizeof(WRITE_PROCESS_MEMORY), nullptr, 0, nullptr, nullptr);
  }

  // Write kernel memory

  template<typename T>
  static void WriteKernelMemory(DWORD64 base, T value)
  {
    WRITE_KERNEL_MEMORY request{ base, sizeof(T), &value };
    DeviceIoControl(g_driverHandle, IOCTRL_WRITE_KERNEL_MEMORY, &request, sizeof(WRITE_KERNEL_MEMORY), nullptr, 0, nullptr, nullptr);
  }

  template<typename T>
  static void WriteKernelMemory(DWORD64 base, T* buffer, DWORD32 count)
  {
    WRITE_KERNEL_MEMORY request{ base, sizeof(T) * count, buffer };
    DeviceIoControl(g_driverHandle, IOCTRL_WRITE_KERNEL_MEMORY, &request, sizeof(WRITE_KERNEL_MEMORY), nullptr, 0, nullptr, nullptr);
  }

  // Scan process memory

  template<typename T>
  static void ScanProcessFirst(DWORD32 pid, DWORD64 base, T value, SCAN_TYPE type, std::vector<DWORD64>& scans)
  {
    SCAN_PROCESS_FIRST request{ pid, base, sizeof(T), &value, (DWORD32)type };
    DWORD32 count = 0;
    DeviceIoControl(g_driverHandle, IOCTRL_SCAN_PROCESS_FIRST, &request, sizeof(SCAN_PROCESS_FIRST), &count, sizeof(DWORD32), nullptr, nullptr);
    scans.clear();
    if (count > 0)
    {
      scans.resize(count);
      DeviceIoControl(g_driverHandle, IOCTRL_READ_SCAN_RESULTS, &count, sizeof(DWORD32), &scans[0], sizeof(DWORD64) * count, nullptr, nullptr);
    }
  }

  template<typename T>
  static void ScanProcessNext(DWORD32 pid)
  {
    //SCAN_PROCESS_NEXT request{ pid };
    //DeviceIoControl(g_driverHandle, IOCTRL_SCAN_PROCESS_NEXT, &request, sizeof(SCAN_PROCESS_NEXT), nullptr, 0, nullptr, nullptr);
  }
}

#endif
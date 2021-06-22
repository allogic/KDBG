#ifndef _IOCTRL_H
#define _IOCTRL_H

#include "global.h"

#define KDRV_CTRL_DUMP_KRNL_IMAGES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0100, METHOD_OUT_DIRECT, FILE_SPECIAL_ACCESS)
#define KDRV_CTRL_DUMP_PROCESSES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0101, METHOD_OUT_DIRECT, FILE_SPECIAL_ACCESS)
#define KDRV_CTRL_DUMP_REGISTERS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0102, METHOD_OUT_DIRECT, FILE_SPECIAL_ACCESS)

#define KDRV_CTRL_MEMORY_READ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0200, METHOD_OUT_DIRECT, FILE_SPECIAL_ACCESS)
#define KDRV_CTRL_MEMORY_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0201, METHOD_OUT_DIRECT, FILE_SPECIAL_ACCESS)

#define KDRV_CTRL_THREAD_SUSPEND CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0300, METHOD_OUT_DIRECT, FILE_SPECIAL_ACCESS)
#define KDRV_CTRL_THREAD_RESUME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0301, METHOD_OUT_DIRECT, FILE_SPECIAL_ACCESS)

/////////////////////////////////////////////////
/// Dump requests
/////////////////////////////////////////////////

typedef struct _KDRV_REQ_DUMP_KRNL_IMAGES
{
  typedef struct
  {
    CHAR Name[256];
    PVOID Base;
    ULONG Size;
  } MODULE, * PMODULE;
  PMODULE Modules;
  ULONG ModuleCount;
} KDRV_REQ_DUMP_KRNL_IMAGES, * PKDRV_REQ_DUMP_KRNL_IMAGES;
typedef struct _KDRV_REQ_DUMP_PROCESSES
{
  typedef struct
  {
    ULONG Tid;
    PVOID Base;
    ULONG State;
  } THREAD, * PTHREAD;
  typedef struct
  {
    ULONG Pid;
    WCHAR Name[256];
    PTHREAD Threads;
  } PROCESS, * PPROCESS;
  PPROCESS Processes;
  ULONG ProcessCount;
  ULONG ThreadCount;
} KDRV_REQ_DUMP_PROCESSES, * PKDRV_REQ_DUMP_PROCESSES;
typedef struct _KDRV_REQ_DUMP_REGISTERS
{
  ULONG Tid;
  CONTEXT Registers;
} KDRV_REQ_DUMP_REGISTERS, * PKDRV_REQ_DUMP_REGISTERS;

/////////////////////////////////////////////////
/// Memory requests
/////////////////////////////////////////////////

typedef struct _KDRV_REQ_MEMORY_READ
{
  ULONG Pid;
  PWCHAR ModuleName;
  PBYTE Buffer;
  ULONG Offset;
  ULONG Size;
} KDRV_REQ_MEMORY_READ, * PKDRV_REQ_MEMORY_READ;
typedef struct _KDRV_REQ_MEMORY_WRITE
{
  ULONG Pid;
  PWCHAR ModuleName;
  PBYTE Buffer;
  ULONG Offset;
  ULONG Size;
} KDRV_REQ_MEMORY_WRITE, * PKDRV_REQ_MEMORY_WRITE;

/////////////////////////////////////////////////
/// Thread requests
/////////////////////////////////////////////////

typedef struct _KDRV_REQ_THREAD_SUSPEND
{
  ULONG Pid;
  ULONG Tid;
} KDRV_REQ_THREAD_SUSPEND, * PKDRV_REQ_THREAD_SUSPEND;
typedef struct _KDRV_REQ_THREAD_RESUME
{
  ULONG Pid;
  ULONG Tid;
} KDRV_REQ_THREAD_RESUME, * PKDRV_REQ_THREAD_RESUME;

#endif
#ifndef _IOCTRL_H
#define _IOCTRL_H

#include "global.h"

/*
* I/O control codes.
*/

#define KMOD_REQ_PROCESS_ATTACH  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0100, METHOD_IN_DIRECT, FILE_SPECIAL_ACCESS)
#define KMOD_REQ_PROCESS_MODULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0101, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define KMOD_REQ_PROCESS_THREADS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0102, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define KMOD_REQ_MEMORY_READ     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0200, METHOD_IN_DIRECT, FILE_SPECIAL_ACCESS)
#define KMOD_REQ_MEMORY_WRITE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0201, METHOD_IN_DIRECT, FILE_SPECIAL_ACCESS)

/*
* I/O request types.
*/

typedef struct _REQ_PROCESS_ATTACH
{
  struct
  {
    ULONG Pid = 0;
  } In;
} REQ_PROCESS_ATTACH, * PREQ_PROCESS_ATTACH;
typedef struct _REQ_PROCESS_MODULES
{
  struct
  {
    SIZE_T Size = 0;
  } In;
  struct
  {
    PVOID Buffer = NULL;
    SIZE_T Size = 0;
  } Out;
} REQ_PROCESS_MODULES, * PREQ_PROCESS_MODULES;
typedef struct _REQ_PROCESS_THREADS
{
  struct
  {
    SIZE_T Size = 0;
  } In;
  struct
  {
    PVOID Buffer = NULL;
    SIZE_T Size = 0;
  } Out;
} REQ_PROCESS_THREADS, * PREQ_PROCESS_THREADS;

typedef struct _REQ_MEMORY_READ
{
  struct
  {
    WCHAR Name[256] = {};
    ULONG Offset = 0;
    SIZE_T Size = 0;
  } In;
  struct
  {
    ULONG64 Base = 0;
    PVOID Buffer = NULL;
  } Out;
} REQ_MEMORY_READ, * PREQ_MEMORY_READ;
typedef struct _REQ_MEMORY_WRITE
{
  struct
  {
    WCHAR Name[256] = {};
    ULONG Offset = 0;
    SIZE_T Size = 0;
  } In;
  struct
  {
    ULONG64 Base = 0;
    PVOID Buffer = NULL;
  } Out;
} REQ_MEMORY_WRITE, * PREQ_MEMORY_WRITE;

#endif
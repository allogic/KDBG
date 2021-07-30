#ifndef _IOCTRL_H
#define _IOCTRL_H

#include "global.h"

/*
* Write control codes.
*/

#define KM_WRITE_MEMORY_PROCESS 100
#define KM_WRITE_MEMORY_KERNEL  101

/*
* Read control codes.
*/

#define KM_READ_MEMORY_PROCESS  200
#define KM_READ_MEMORY_KERNEL   201

#define KM_READ_MODULES_PROCESS 202
#define KM_READ_MODULES_KERNEL  203

#define KM_READ_THREADS_PROCESS 204

/*
* Write request types.
*/

typedef struct _WRITE_MEMORY_PROCESS
{
  ULONG Pid = NULL;
  WCHAR ImageName[256];
  ULONG Offset = 0;
  ULONG Size = 0;
  CHAR Bytes[1024];
} WRITE_MEMORY_PROCESS, * PWRITE_MEMORY_PROCESS;
typedef struct _WRITE_MEMORY_KERNEL
{
  WCHAR ImageName[256];
  ULONG Offset = 0;
  ULONG Size = 0;
  CHAR Bytes[1024];
} WRITE_MEMORY_KERNEL, * PWRITE_MEMORY_KERNEL;

/*
* Read request types.
*/

typedef struct _READ_MEMORY_PROCESS
{
  ULONG Pid = NULL;
  WCHAR ImageName[256];
  ULONG Offset = 0;
  ULONG Size = 0;
} READ_MEMORY_PROCESS, * PREAD_MEMORY_PROCESS;
typedef struct _READ_MEMORY_KERNEL
{
  WCHAR ImageName[256];
  ULONG Offset = 0;
  ULONG Size = 0;
} READ_MEMORY_KERNEL, * PREAD_MEMORY_KERNEL;

#endif
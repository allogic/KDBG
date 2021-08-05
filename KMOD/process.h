#ifndef _PROCESS_H
#define _PROCESS_H

#include "global.h"

NTSTATUS
KmGetProcessImageBase(
  ULONG pid,
  PWCHAR imageName,
  PVOID* base);

NTSTATUS
KmGetKernelImageBase(
  PCHAR imageName,
  PVOID* imageBase);

#endif
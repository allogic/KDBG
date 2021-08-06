/*
* @author allogic
* @file process.h
* @brief ASLR utilities.
* @copyright allogic 2021. All Rights Reserved.
*/

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
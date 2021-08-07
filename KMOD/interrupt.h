/*
* @author allogic
* @file interrupt.h
* @brief Interrupt hook handler.
* @copyright allogic 2021. All Rights Reserved.
*/

#ifndef _INTERRUPT_H
#define _INTERRUPT_H

#include "global.h"

/*
* ASM utilities.
*/

#pragma pack(1)
typedef struct
{
  ULONG64 EIP;
  WORD CS;
} JUMPBACK, * PJUMPBACK;
#pragma pack()

/*
* x64 Interrupt Descriptor Table
*/

#pragma pack(1)
typedef struct _INT_VECTOR
{
  WORD LowOffset;
  WORD Selector;
  BYTE Unused;
  BYTE AccessFlags;
  WORD HighOffset;
  DWORD	TopOffset;
  DWORD	Reserved;
} INT_VECTOR, * PINT_VECTOR;
#pragma pack()

#pragma pack(2)
typedef struct _IDT
{
  WORD Limit;
  PINT_VECTOR Vector;
} IDT, * PIDT;
#pragma pack()

VOID
GetIDT(PIDT idt);

VOID
SetIDT(PIDT idt);

/*
* Interrupt utilities.
*/

typedef struct _INTERRUPT_HOOK
{
  BOOL Hooked;
  WORD OrigCS;
  ULONG64 OrigEIP;
} INTERRUPT_HOOK, * PINTERRUPT_HOOK;

VOID
EnableInterrupts();

VOID
DisableInterrupts();

VOID
HookInterrupt(
  BYTE intNr,
  WORD newCS,
  ULONG64 newEIP,
  PJUMPBACK jumpback);

#endif
#ifndef INTERRUPT_H
#define INTERRUPT_H

#include "global.h"

/*
* WinDbg:
*  > ?? sizeof(X)    // get byte size
*  > !idt            // dump IDT
*  > dt _KIDTENTRY64 // interrupt descriptor table
*  > dt _KINTERRUPT  // single kernel interrupt entry
*  > dt _KPCR        // process control region
*  > dt _KPRCB       // process control block
*/

/*
* x64 Interrupt descriptor table
*/

typedef union _KIDTENTRY64
{
  struct
  {
    WORD OffsetLow;
    WORD Selector;
    WORD IstIndex : 3;
    WORD Reserved0 : 5;
    WORD Type : 5;
    WORD Dp1 : 2;
    WORD Present : 1;
    WORD OffsetMiddle;
    DWORD OffsetHigh;
    DWORD Reserved1;
  };
  LWORD Alignment;
} KIDTENTRY64, * PKIDTENTRY64;

typedef struct _KIDT64
{
  WORD Padding[3];
  WORD Limit;
  PKIDTENTRY64 Table;
} KIDT64, * PKIDT64;

/*
* Interrupt utils
*/

typedef struct _ISRHOOK
{
  BYTE Active;
  LWORD Original;
  LWORD Current;
} ISRHOOK, * PISRHOOK;

PKIDTENTRY64
KmGetIDT();

LWORD
KmGetISR(
  PKIDTENTRY64 idt,
  BYTE interruptNumber);

VOID
KmSetISR(
  PKIDTENTRY64 idt,
  BYTE interruptNumber,
  LWORD newIsr);

VOID
KmHookInterrupt(
  BYTE interruptNumber,
  LWORD newIsr);

VOID
KmRestoreInterrupts();

#endif
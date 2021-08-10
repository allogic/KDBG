/*
* @author allogic
* @file debugger.h
* @brief Windows kernel debugger.
* @copyright allogic 2021. All Rights Reserved.
*/

#ifndef _DEBUGGER_H
#define _DEBUGGER_H

#include "global.h"
#include "interrupt.h"

#pragma pack(4)
typedef struct _DEBUG_STACK_STATE
{
  ULONG64 ThreadId;
  ULONG64 RFlags;
  ULONG64 RAX;
  ULONG64 RBX;
  ULONG64 RCX;
  ULONG64 RDX;
  ULONG64 RSI;
  ULONG64 RDI;
  ULONG64 RBP;
  ULONG64 RSP;
  ULONG64 RIP;
  ULONG64 R8;
  ULONG64 R9;
  ULONG64 R10;
  ULONG64 R11;
  ULONG64 R12;
  ULONG64 R13;
  ULONG64 R14;
  ULONG64 R15;
  ULONG64 CS;
  ULONG64 DS;
  ULONG64 ES;
  ULONG64 FS;
  ULONG64 GS;
  ULONG64 SS;
  ULONG64 DR0;
  ULONG64 DR1;
  ULONG64 DR2;
  ULONG64 DR3;
  ULONG64 DR6;
  ULONG64 DR7;
  BYTE FxState[512];
  ULONG64 LBRCount;
  ULONG64 LBR[16];
} DEBUG_STACK_STATE, * PDEBUG_STACK_STATE;
#pragma pack()

typedef enum _BREAK_TYPE
{
  OnInstruction,
  OnWrites,
  OnIOAccess,
  OnReadsAndWrites,
} BREAK_TYPE;
typedef enum _BREAK_LENGTH
{
  x1Byte,
  x2Byte,
  x8Byte,
  x4Byte,
} BREAK_LENGTH;

typedef struct _DEBUG_STATE
{
  struct
  {
    BOOL Active;
    ULONG64 Address;
    BREAK_TYPE  BreakType;
    BREAK_LENGTH BreakLength;
  } Breakpoints[4];
  BOOL GlobalDebug; //If set all threads of every process will raise an interrupt on taskswitch
  PULONG64 LastStackPointer;
  PULONG64 LastRealDebugRegisters;
  HANDLE LastThreadID;
  BOOL HandledLastEvent;
} DEBUG_STATE, * PDEBUG_STATE;

VOID
KmInitializeDebugger();

INT
BreakpointHandler(
  PULONG64 stackpointer,
  PULONG64 debugRegisters,
  PULONG64 lbrStack);

INT
Int1Handler(
  PULONG64 stackpointer,
  PULONG64 debugRegisters);

INT
Int1CEntry(
  PULONG64 stackpointer);

NTSTATUS
GetDebuggerState(
  PDEBUG_STACK_STATE debugStackState);

NTSTATUS
SetDebuggerState(
  PDEBUG_STACK_STATE debugStackState);

NTSTATUS
DebugContinue();

NTSTATUS
WaitForDebugEvent();

#endif
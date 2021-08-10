#include "debugger.h"

DEBUG_STATE DebugState;

KEVENT EventWaitForContinue; //event for kernelmode. Waits till it's set by usermode (usermode function: DBK_Continue_Debug_Event sets it)
KEVENT EventCanBreak; //event for kernelmode. Waits till a break has been handled so a new one can enter
KEVENT EventWaitForDebugEvent; //event for usermode. Waits till it's set by a debugged event

JUMPBACK Int1Jumpback;

EXTERN_C WORD GetCS();
EXTERN_C VOID Int1AsmEntry();

VOID
KmInitializeDebugger()
{
  //KeInitializeEvent(&EventWaitForContinue, SynchronizationEvent, FALSE);
  //KeInitializeEvent(&EventCanBreak, SynchronizationEvent, TRUE); //true so the first can enter
  //KeInitializeEvent(&EventWaitForDebugEvent, SynchronizationEvent, FALSE);

  // create stack snapshots for physical cpu

  HookInterrupt(1, GetCS() & 0xfff8, Int1AsmEntry, &Int1Jumpback);
}

INT
BreakpointHandler(
  PULONG64 stackpointer,
  PULONG64 debugRegisters,
  PULONG64 lbrStack)
{
  return 0; // impl!
}

INT
Int1Handler(
  PULONG64 stackpointer,
  PULONG64 debugRegisters)
{
  return 0; // impl!
}

INT
Int1CEntry(
  PULONG64 stackpointer)
{
  return 0; // impl!
}

VOID
AttachDebugger(
  ULONG pid)
{
  //Int1Jumpback.EIP = inthook_getOriginalEIP(1);
  //Int1Jumpback.CS = inthook_getOriginalCS(1);
}

NTSTATUS
GetDebuggerState(
  PDEBUG_STACK_STATE debugStackState)
{
  NTSTATUS status = STATUS_SUCCESS;
  return status;
}

NTSTATUS
SetDebuggerState(
  PDEBUG_STACK_STATE debugStackState)
{
  NTSTATUS status = STATUS_SUCCESS;
  return status;
}

NTSTATUS
DebugContinue()
{
  NTSTATUS status = STATUS_SUCCESS;
  //KeSetEvent(&EventWaitForContinue, 0, FALSE);
  return status;
}

NTSTATUS
WaitForDebugEvent()
{
  NTSTATUS status = STATUS_SUCCESS;
  //KeWaitForSingleObject(&EventWaitForDebugEvent, UserRequest, KernelMode, TRUE, NULL);
  return status;
}

VOID
SetBreakpoint(
  ULONG breakpointNr,
  ULONG64 address)
{

}

VOID
RemBreakpoint(
  ULONG breakpointNr)
{

}
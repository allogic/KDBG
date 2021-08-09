#include "debugger.h"

JUMPBACK Int1JumpBackLocation;

EXTERN_C WORD getCS();
EXTERN_C WORD getSS();
EXTERN_C WORD getDS();
EXTERN_C WORD getES();
EXTERN_C WORD getFS();
EXTERN_C WORD getGS();
EXTERN_C ULONG64 getRSP();
EXTERN_C ULONG64 getRBP();
EXTERN_C ULONG64 getRAX();
EXTERN_C ULONG64 getRBX();
EXTERN_C ULONG64 getRCX();
EXTERN_C ULONG64 getRDX();
EXTERN_C ULONG64 getRSI();
EXTERN_C ULONG64 getRDI();
EXTERN_C ULONG64 getR8();
EXTERN_C ULONG64 getR9();
EXTERN_C ULONG64 getR10();
EXTERN_C ULONG64 getR11();
EXTERN_C ULONG64 getR12();
EXTERN_C ULONG64 getR13();
EXTERN_C ULONG64 getR14();
EXTERN_C ULONG64 getR15();
EXTERN_C ULONG64 getAccessRights(ULONG64 segment);
EXTERN_C ULONG64 getSegmentLimit(ULONG64 segment);

EXTERN_C VOID Int1AEntry();

VOID
KmInitializeDebugger()
{
  HookInterrupt(1, getCS() & 0xfff8, Int1AEntry, &Int1JumpBackLocation);
}

INT
Int1CEntry(
  PULONG64 stackpointer)
{
  return 0;
}

VOID
KmSetSoftwareBreakpoint(
  PCONTEXT context)
{
  // continue from gdb_input.h
  //KeSetContextPc(context, 0xCC); // int3
  //KdpSetSingleStep(context);
  //PKTRAP_FRAME trapFrame = KeGetTrapFramePc(context);
  //KMOD_LOG_INFO("Trap flag %llu\n", );
}

VOID
KmSetHardwareBreakpoint()
{

}
#include "debugger.h"

JUMPBACK Int1JumpBackLocation;

extern WORD getCS();
extern WORD getSS();
extern WORD getDS();
extern WORD getES();
extern WORD getFS();
extern WORD getGS();
extern ULONG64 getRSP();
extern ULONG64 getRBP();
extern ULONG64 getRAX();
extern ULONG64 getRBX();
extern ULONG64 getRCX();
extern ULONG64 getRDX();
extern ULONG64 getRSI();
extern ULONG64 getRDI();
extern ULONG64 getR8();
extern ULONG64 getR9();
extern ULONG64 getR10();
extern ULONG64 getR11();
extern ULONG64 getR12();
extern ULONG64 getR13();
extern ULONG64 getR14();
extern ULONG64 getR15();
extern ULONG64 getAccessRights(ULONG64 segment);
extern ULONG64 getSegmentLimit(ULONG64 segment);
extern VOID interrupt1_asmentry();

VOID
KmInitializeDebugger()
{
  HookInterrupt(1, getCS() & 0xfff8, interrupt1_asmentry, &Int1JumpBackLocation);
}

INT
interrupt1_centry(
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
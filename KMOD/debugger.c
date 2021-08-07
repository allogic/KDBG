#include "debugger.h"

VOID
KmSetSoftwareBreakpoint(
  PCONTEXT context)
{
  // continue from gdb_input.h
  KeSetContextPc(context, 0xCC); // int3
  KdpSetSingleStep(context);
  //PKTRAP_FRAME trapFrame = KeGetTrapFramePc(context);
  //KMOD_LOG_INFO("Trap flag %llu\n", );
}

VOID
KmSetHardwareBreakpoint()
{

}
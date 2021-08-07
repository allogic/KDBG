#include "interrupt.h"

INTERRUPT_HOOK InterruptHooks[256];

VOID
GetIDT(PIDT idt)
{
  __sidt(idt);
}

VOID
SetIDT(PIDT idt)
{
  __lidt(idt);
}

VOID
EnableInterrupts()
{
  _enable();
}

VOID
DisableInterrupts()
{
  _disable();
}

VOID
HookInterrupt(
  BYTE intNr,
  WORD newCS,
  ULONG64 newEIP,
  PJUMPBACK jumpback)
{
  IDT idt;
  GetIDT(&idt);
  KM_LOG_INFO();
  DbgPrint("int%d newCS=%X newEIP=%p jumpbacklocation=%p\n", intNr, newCS, (PVOID)newEIP, jumpback);
  INT_VECTOR newVector;
  newVector.HighOffset = (WORD)((DWORD)(newEIP >> 16));
  newVector.LowOffset = (WORD)newEIP;
  newVector.Selector = newCS;
  newVector.Unused = 0;
  newVector.AccessFlags = idt.Vector[intNr].AccessFlags;
  newVector.TopOffset = (newEIP >> 32);
  newVector.Reserved = 0;
  KM_LOG_INFO("int%d will now go to %X:%p\n", intNr, newCS, (PVOID)newEIP);
}
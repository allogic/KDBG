#include "interrupt.h"

/*
* Active traps & payloads
*/

ISRHOOK IsrHooks[256];

extern VOID KmInt1Trap(); // KiDebugTrapOrFault
extern VOID KmInt3Trap(); // KiBreakpointTrap
extern VOID KmInt14Trap(); // KiPageFault

VOID
KmInt1Payload() // KiDebugTrapOrFault
{
  KM_LOG_INFO("KmInt1Payload\n");
}

VOID
KmInt3Payload() // KiBreakpointTrap
{
  KM_LOG_INFO("KmInt3Payload\n");
}

VOID
KmInt14Payload() // KiPageFault
{
  KM_LOG_INFO("KmInt14Payload\n");
}

/*
* Interrupt utils
*/

PKIDTENTRY64
KmGetIDT()
{
  KIDT64 idt;
  __sidt(&idt.Limit);
  return idt.Table;
}

LWORD
KmGetISR(
  PKIDTENTRY64 idt,
  BYTE interruptNumber)
{
  return (LWORD)((LWORD)idt[interruptNumber].OffsetHigh << 32)
    | ((LWORD)((LWORD)idt[interruptNumber].OffsetMiddle << 16)
    | idt[interruptNumber].OffsetLow);
}

VOID
KmSetISR(
  PKIDTENTRY64 idt,
  BYTE interruptNumber,
  LWORD newIsr)
{
  idt[interruptNumber].OffsetHigh = newIsr >> 32;
  idt[interruptNumber].OffsetMiddle = (newIsr << 32) >> 48;
  idt[interruptNumber].OffsetLow = newIsr & 0xffff;
}

VOID
KmHookInterrupt(
  BYTE interruptNumber,
  LWORD newIsr)
{
  PKIDTENTRY64 idt = KmGetIDT();
  KM_LOG_INFO("IDT base %p\n", (PVOID)idt);
  LWORD isr = KmGetISR(idt, interruptNumber);
  KIRQL irql;
  LWORD cr0;
  KAFFINITY activeProcessors = KeQueryActiveProcessors();
  for (KAFFINITY affinity = 1; activeProcessors; affinity <<= 1, activeProcessors >>= 1)
  {
    if (activeProcessors & 1)
    {
      KeSetSystemAffinityThread(affinity);
      irql = KeRaiseIrqlToDpcLevel();
      cr0 = __readcr0();
      cr0 &= 0xfffffffffffeffff;
      __writecr0(cr0);
      _disable();
      KmSetISR(idt, interruptNumber, newIsr);
      cr0 = __readcr0();
      cr0 |= 0x10000;
      _enable();
      __writecr0(cr0);
      KeLowerIrql(irql);
      KeRevertToUserAffinityThread();
    }
  }
  IsrHooks[interruptNumber].Active = !IsrHooks[interruptNumber].Active;
  IsrHooks[interruptNumber].Original = isr;
  IsrHooks[interruptNumber].Current = newIsr;
  KM_LOG_INFO("Original %p\n", (PVOID)IsrHooks[interruptNumber].Original);
  KM_LOG_INFO("Current %p\n", (PVOID)IsrHooks[interruptNumber].Current);
}

VOID
KmInitInterrupts()
{
  //KmHookInterrupt(1, KmInt1Trap);
  //KmHookInterrupt(3, KmInt3Trap);
  KmHookInterrupt(14, KmInt14Trap);
}

VOID
KmRestoreInterrupts()
{
  //KmHookInterrupt(1, IsrHooks[1].Original);
  //KmHookInterrupt(3, IsrHooks[3].Original);
  KmHookInterrupt(14, IsrHooks[14].Original);
}
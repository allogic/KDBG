#include "interrupt.h"
#include "stack.h"

/*
* Active traps & payloads
*/

LWORD IsrInt1Original;
LWORD IsrInt3Original;
LWORD IsrInt14Original;

extern VOID KmInt1Trap(); // KiDebugTrapOrFault
extern VOID KmInt3Trap(); // KiBreakpointTrap
extern VOID KmInt14Trap(); // KiPageFault

VOID
KmInt1Payload() // KiDebugTrapOrFault
{
  //KM_LOG_INFO("KmInt1Payload\n");
}

VOID
KmInt3Payload() // KiBreakpointTrap
{
  //KM_LOG_INFO("KmInt3Payload\n");
}

VOID
KmInt14Payload(
  PSTACK stack) // KiPageFault
{
  //KM_LOG_INFO("KmInt14Payload\n");
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
  LWORD newIsr,
  LWORD* origIsr)
{
  PKIDTENTRY64 idt = NULL;
  LWORD isr = 0;
  LWORD isrPrev = 0;
  KIRQL irql = 0;
  LWORD cr0 = 0;
  KAFFINITY activeProcessors = KeQueryActiveProcessors();
  KAFFINITY affinity = 1;
  ULONG i = 0;
  for (; activeProcessors; affinity <<= 1, activeProcessors >>= 1, i++)
  {
    if (activeProcessors & 1)
    {
      KeSetSystemAffinityThread(affinity);
      idt = KmGetIDT();
      isrPrev = isr;
      isr = KmGetISR(idt, interruptNumber);
      KM_LOG_INFO("IDT:%p ISR:%p\n", (PVOID)idt, (PVOID)isr);
      if (i > 0 && isr != isrPrev)
      {
        KM_LOG_ERROR("ISR difference detected, Prev:%p Curr:%p\n", (PVOID)isrPrev, (PVOID)isr);
      }
      irql = KeRaiseIrqlToDpcLevel();
      cr0 = __readcr0();
      cr0 &= 0xfffffffffffeffff;
      __writecr0(cr0);
      _disable();
      if (origIsr)
      {
        *origIsr = isr;
      }
      KmSetISR(idt, interruptNumber, newIsr);
      cr0 = __readcr0();
      cr0 |= 0x10000;
      _enable();
      __writecr0(cr0);
      KeLowerIrql(irql);
      KeRevertToUserAffinityThread();
    }
  }
  KM_LOG_INFO("ISR successfully hooked, Orig:%p Curr:%p\n\n", (PVOID)isr, (PVOID)newIsr);
}

VOID
KmInitInterrupts()
{
  KmHookInterrupt(1, KmInt1Trap, &IsrInt1Original);
  KmHookInterrupt(3, KmInt3Trap, &IsrInt3Original);
  KmHookInterrupt(14, KmInt14Trap, &IsrInt14Original);
}

VOID
KmRestoreInterrupts()
{
  KmHookInterrupt(1, IsrInt1Original, NULL);
  KmHookInterrupt(3, IsrInt3Original, NULL);
  KmHookInterrupt(14, IsrInt14Original, NULL);
}
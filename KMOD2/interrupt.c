#include "interrupt.h"

/*
* Active hooks
*/

ISRHOOK IsrHooks[256];

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
  return (LWORD)(idt[interruptNumber].OffsetHigh << 32)
    | ((LWORD)(idt[interruptNumber].OffsetMiddle << 16)
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
  _disable();
  if (!IsrHooks[interruptNumber].Active)
  {
    PKIDTENTRY64 idt = KmGetIDT();
    LWORD isr = KmGetISR(idt, interruptNumber);
    KM_LOG_INFO("ISR initial %p\n", (PVOID)isr);
    KAFFINITY activeProcessors = KeQueryActiveProcessors();
    for (KAFFINITY affinity = 1; activeProcessors; affinity <<= 1, activeProcessors >>= 1)
    {
      if (activeProcessors & 1)
      {
        KeSetSystemAffinityThread(affinity);
        idt = KmGetIDT();
        isr = KmGetISR(idt, interruptNumber);
        KM_LOG_INFO("ISR %p\n", (PVOID)isr);
        KIRQL irql = KeRaiseIrqlToDpcLevel();
        LWORD cr0 = __readcr0();
        cr0 &= 0xfffffffffffeffff;
        __writecr0(cr0);
        //_disable();
        KmSetISR(idt, interruptNumber, newIsr);
        cr0 = __readcr0();
        cr0 |= 0x10000;
        //_enable();
        __writecr0(cr0);
        KeLowerIrql(irql);
        KeRevertToUserAffinityThread();
      }
    }
    //IsrHooks[interruptNumber].Active = 1;
    //IsrHooks[interruptNumber].Original = isr; // no loop pls
    IsrHooks[interruptNumber].Current = newIsr;
  }
  _enable();
}

VOID
KmRestoreInterrupts()
{
  PKIDTENTRY64 idt = KmGetIDT();
  for (BYTE i = 0; i < 256; i++)
  {
    if (IsrHooks[i].Active)
    {
      KAFFINITY activeProcessors = KeQueryActiveProcessors();
      for (KAFFINITY affinity = 1; activeProcessors; affinity <<= 1, activeProcessors >>= 1)
      {
        if (activeProcessors & 1)
        {
          KeSetSystemAffinityThread(affinity);
          KIRQL irql = KeRaiseIrqlToDpcLevel();
          LWORD cr0 = __readcr0();
          cr0 &= 0xfffffffffffeffff;
          __writecr0(cr0);
          _disable();
          KmSetISR(idt, i, IsrHooks[i].Original);
          cr0 = __readcr0();
          cr0 |= 0x10000;
          _enable();
          __writecr0(cr0);
          KeLowerIrql(irql);
          KeRevertToUserAffinityThread();
        }
      }
      IsrHooks[i].Active = 0;
      IsrHooks[i].Original = 0x0;
      IsrHooks[i].Current = 0x0;
    }
  }
}
#include "interrupt.h"

VOID
KmEnableInterrupts()
{
  _enable();
}

VOID
KmDisableInterrupts()
{
  _disable();
}

PKIDTENTRY64
KmGetIDT()
{

}

VOID
KmHookInterrupt(
  BOOL interrupt)
{
  KAFFINITY activeProcessors = KeQueryActiveProcessors();
  for (KAFFINITY affinity = 1; activeProcessors; affinity <<= 1, activeProcessors >>= 1)
  {
    if (activeProcessors & 1)
    {
      KeSetSystemAffinityThread(affinity);
      KM_LOG_INFO("Bound thread to CPU %u\n", (DWORD)affinity);
      KIDT64 idt;
      __sidt(&idt.Limit);
      DWORD n = (idt.Limit + 1) / sizeof(KIDTENTRY64);
      PKIDTENTRY64 entry = idt.Table;
      if (n)
      {
        do
        {
          // Hook IDT here..
          KM_LOG_INFO("IDT entry %u\n", n);
          KM_LOG_INFO("\tIstIndex %u\n", entry->IstIndex);
          KM_LOG_INFO("\tType %u\n", entry->Type);
          KM_LOG_INFO("\tDp1 %u\n", entry->Dp1);
          KM_LOG_INFO("\tPresent %u\n", entry->Present);
          KM_LOG_INFO("\tISR %p\n", (PVOID)((LWORD)(entry->OffsetHigh << 32) | ((LWORD)(entry->OffsetMiddle << 16) | entry->OffsetLow)));
          KM_LOG_INFO("\n");
        } while (entry++, --n);
      }
    }
  }
  KeRevertToUserAffinityThread();
}
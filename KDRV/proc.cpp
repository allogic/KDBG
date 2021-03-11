#include "proc.h"

PLDR_DATA_TABLE_ENTRY GetMainModuleDataTableEntry(PPEB64 peb)
{
  if (SanitizeUserPointer(peb, sizeof(PEB64)))
  {
    if (peb->Ldr)
    {
      if (SanitizeUserPointer(peb->Ldr, sizeof(PEB_LDR_DATA)))
      {
        if (!peb->Ldr->Initialized)
        {
          int initLoadCount = 0;

          while (!peb->Ldr->Initialized && initLoadCount++ < 4)
          {
            DriverSleep(250);
          }
        }

        if (peb->Ldr->Initialized)
        {
          return CONTAINING_RECORD(peb->Ldr->InLoadOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        }
      }
    }
  }
  return NULL;
}
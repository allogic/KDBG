#include "global.h"

INT main(INT argc, PCHAR argv[])
{
  if (strcmp(argv[1], "/ScanContext") == 0)
  {
#pragma pack(push, 1)
    struct
    {
      ULONG Pid;
      ULONG Tid;
    } args
    {
      strtoul(argv[2], NULL, 10),
      strtoul(argv[3], NULL, 10),
    };
#pragma pack(pop)
    for (SIZE_T i = 0; i < sizeof(args); ++i)
    {
      printf("%02X", ((PBYTE)&args)[i]);
    }
  }
  return 0;
}
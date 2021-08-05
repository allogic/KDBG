#include <windows.h>

#include <stdio.h>

ULONG
TestThread(PVOID context)
{
  PULONG value = (PULONG)context;
  printf("%10lu holding memory address %p\n", GetCurrentThreadId(), value);
  while (TRUE)
  {
    (*value)++;
    Sleep(1000);
  }
  return 0;
}

INT
wmain(
  INT argc,
  PWCHAR argv[])
{
  ULONG values[32] = {};
  for (ULONG i = 0; i < 32; ++i)
  {
    values[i] = i;
    CreateThread(NULL, 0, TestThread, &values[i], 0, NULL);
  }
  while (TRUE)
  {
    Sleep(1000);
  }
  return 0;
}
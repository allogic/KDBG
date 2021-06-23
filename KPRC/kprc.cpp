#include <stdio.h>
#include <windows.h>

DWORD Thread(LPVOID param)
{
  ULONG running = 1;
  while (running)
  {
    printf("Thread: %u called\n", GetCurrentThreadId());
    Sleep(10000);
  }
  return 0;
}

INT wmain(INT argc, PWCHAR argv[])
{
  ULONG threadCount = wcstoul(argv[1], NULL, 10);
  for (ULONG i = 0; i < threadCount; ++i)
  {
    DWORD tid = 0;
    CreateThread(NULL, 0, Thread, NULL, 0, &tid);
    printf("Thread %u created\n", tid);
  }
  ULONG running = 1;
  while (running)
  {
    printf("Main: %u called\n", GetCurrentThreadId());
    Sleep(10000);
  }
  return 0;
}
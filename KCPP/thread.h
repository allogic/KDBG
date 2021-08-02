#ifndef _THREAD_H
#define _THREAD_H

#include "global.h"

struct Thread
{
  static void Sleep(long ms)
  {
    LARGE_INTEGER interval;
    interval.QuadPart = -10 * 1000;
    interval.QuadPart *= ms;
    KeDelayExecutionThread(KernelMode, 0, &interval);
  }
};

#endif
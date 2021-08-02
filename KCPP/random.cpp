#include "random.h"

long long unsigned Seed = 0;

void ResetSeed(long long unsigned seed)
{
  if (seed == 0)
  {
    Seed = __rdtsc();
  }
  else
  {
    Seed = seed;
  }
}

long unsigned NextBetween(long unsigned min, long unsigned max)
{
  ULONG const scale = (ULONG)MAXINT32 / (max - min);
  return RtlRandom((PULONG)&Seed) / scale + min;
}
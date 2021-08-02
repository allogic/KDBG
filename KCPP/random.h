#ifndef _RANDOM_H
#define _RANDOM_H

#include "global.h"

void ResetSeed(long long unsigned seed);
long unsigned NextBetween(long unsigned min, long unsigned max);

#endif
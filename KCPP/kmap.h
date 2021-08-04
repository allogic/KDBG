#ifndef _MAP_H
#define _MAP_H

struct pair
{
  char key[256] = {};
  long unsigned value = 0;
};

bool
Emplace(
  char const* key,
  long unsigned value);

void
Values(
  pair* pairs,
  long long unsigned* count);

#endif
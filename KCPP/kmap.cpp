#include "kmap.h"

#include <string>
#include <map>

std::map<std::string, long unsigned> MapStrToLongUnsigned = {};

bool
Emplace(
  char const* key,
  long unsigned value)
{
  auto [_, inserted] = MapStrToLongUnsigned.emplace(key, value);
  return inserted;
}

void
Values(
  pair* pairs,
  long long unsigned* count)
{
  for (auto& [key, value] : MapStrToLongUnsigned)
  {
    memcpy(pairs[*count].key, key.data(), 256);
    pairs[*count].value = value;
    *count++;
  }
}
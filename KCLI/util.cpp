#include "util.h"

using namespace std;

string HexFrom(BYTE byte)
{
  string str{ 2 };
  sprintf(&str[0], "%02X", byte);
  return str;
}

string HexFrom(ULONG64 address)
{
  string str{ 18 };
  sprintf(&str[0], "0x%p", (PVOID)address);
  return str;
}
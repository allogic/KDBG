#include "util.h"

using namespace std;

string ByteToHex(BYTE value)
{
  string str{};
  str.resize(2);
  sprintf(&str[0], "%02X", value);
  return str;
}
wstring ByteToHexW(BYTE value)
{
  wstring str{};
  str.resize(2);
  wsprintf(&str[0], L"%02X", value);
  return str;
}

string ULongToDec(ULONG value)
{
  string str{};
  str.resize(32);
  sprintf(&str[0], "%lu", value);
  return str;
}
wstring ULongToDecW(ULONG value)
{
  wstring str{};
  str.resize(32);
  wsprintf(&str[0], L"%lu", value);
  return str;
}

string AddressToHex(ULONG64 value)
{
  string str{};
  str.resize(32);
  sprintf(&str[0], "0x%p", (PVOID)value);
  return str;
}
wstring AddressToHexW(ULONG64 value)
{
  wstring str{};
  str.resize(32);
  wsprintf(&str[0], L"0x%p", (PVOID)value);
  return str;
}
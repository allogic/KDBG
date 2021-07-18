#ifndef _UTIL_H
#define _UTIL_H

#include "global.h"

std::string ByteToHex(BYTE value);
std::wstring ByteToHexW(BYTE value);

std::string ULongToDec(ULONG value);
std::wstring ULongToDecW(ULONG value);

std::string AddressToHex(ULONG64 value);
std::wstring AddressToHexW(ULONG64 value);

#endif
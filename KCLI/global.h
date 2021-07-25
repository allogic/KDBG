#ifndef _GLOBAL_H
#define _GLOBAL_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <tlhelp32.h>
#include <WinSock2.h>
#include <WS2tcpip.h>

/*
* Standard library.
*/

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <codecvt>

/*
* Disassembler library.
*/

#include <capstone/capstone.h>
#include <capstone/platform.h>

/*
* KCLI specific.
*/

enum State
{
  KCLI_CTRL_MODE,
  KCLI_CMD_MODE,
};

/*
* Logging utilities.
*/

#define _KCLI_STR(VAL) #VAL
#define KCLI_STR(VAL) _KCLI_STR(VAL)

#define KCLI_LOG_INFO(FMT, ...) printf("[+] " FMT, __VA_ARGS__)
#define KCLI_LOG_ERROR(FMT, ...) printf("[-] " FMT, __VA_ARGS__)

#endif
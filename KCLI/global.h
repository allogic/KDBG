#ifndef _GLOBAL_H
#define _GLOBAL_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <windows.h>
#include <tlhelp32.h>

#ifdef __cplusplus
}
#endif

/*
* Standard library.
*/

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <cstdint>

/*
* Disassembler library.
*/

#include <capstone/capstone.h>
#include <capstone/platform.h>

/*
* Linked list.
*/

typedef struct _LIST_NODE
{
  PVOID Next = NULL;
  PVOID Data = NULL;
} LIST_NODE, * PLIST_NODE;

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
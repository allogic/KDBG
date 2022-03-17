#ifndef IOCTRL_H
#define IOCTRL_H

#include "global.h"

/*
* Common Ring0 <-> Ring3 request/response protocol
*/

#define KC_CTRL_DEBUG CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0100, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#endif
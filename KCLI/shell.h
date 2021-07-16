#ifndef _SHELL_H
#define _SHELL_H

#include "global.h"

static USHORT NormalizeMul2(USHORT value)
{
  return value & 1
    ? value ^ 1
    : value;
}

struct Shell
{
  HANDLE                     StdOut;
  HANDLE                     StdIn;
  USHORT                     ScreenWidth;
  USHORT                     ScreenHeight;
  CONSOLE_SCREEN_BUFFER_INFO CsbInfo;
  CONSOLE_CURSOR_INFO        CcInfoOld;
  CONSOLE_CURSOR_INFO        CcInfoNew;
  WORD                       AttrOld;
  DWORD                      FdModeOld;
  DWORD                      FdModeNew;
  INPUT_RECORD               InputEvent;

  Shell();
  virtual ~Shell();

  USHORT Width();
  USHORT Height();

  VOID Poll();

  VOID Clear(USHORT x, USHORT y, USHORT w, USHORT h);
  VOID Frame(USHORT x, USHORT y, USHORT w, USHORT h);

  VOID Char(USHORT x, USHORT y, CHAR chr);

  VOID Text(USHORT x, USHORT y, PCHAR str);
  VOID TextW(USHORT x, USHORT y, PCWCHAR str);
};

#endif
#ifndef _SHELL_H
#define _SHELL_H

#include "global.h"
#include "view.h"

static USHORT NormalizeMul2(USHORT value)
{
  return value & 1
    ? value ^ 1
    : value;
}

struct Shell
{
  HANDLE                     StdOut = INVALID_HANDLE_VALUE;
  HANDLE                     StdIn = INVALID_HANDLE_VALUE;
  USHORT                     ScreenWidth = 0;
  USHORT                     ScreenHeight = 0;
  CONSOLE_SCREEN_BUFFER_INFO CsbInfo = {};
  CONSOLE_CURSOR_INFO        CcInfoOld = {};
  CONSOLE_CURSOR_INFO        CcInfoNew = {};
  WORD                       AttrOld = 0;
  DWORD                      FdModeOld = 0;
  DWORD                      FdModeNew = 0;
  INPUT_RECORD               InputEvent = {};
  WCHAR                      InputBuffer[1024] = {};

  Shell();
  virtual ~Shell();

  USHORT Width();
  USHORT Height();

  VOID Poll(State& state, SIZE_T& selectedView, SIZE_T numViews);
  VOID Read(State& state, View* view);

  VOID Clear(USHORT x, USHORT y, USHORT w, USHORT h);
  VOID Frame(USHORT x, USHORT y, USHORT w, USHORT h);

  VOID Text(USHORT x, USHORT y, PCHAR str);
  VOID TextW(USHORT x, USHORT y, PWCHAR str);
};

#endif
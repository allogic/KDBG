#ifndef _SHELL_H
#define _SHELL_H

#include "global.h"
#include "view.h"

static USHORT NormalizeMul2(USHORT value)
{
  return value & 1 ? value ^ 1 : value; // make me branchless
}

static BOOL KeyDown(INPUT_RECORD& event, WORD keyCode)
{
  return event.EventType == KEY_EVENT
    && event.Event.KeyEvent.bKeyDown
    && event.Event.KeyEvent.wVirtualKeyCode == keyCode;
}
static BOOL KeyUp(INPUT_RECORD& event, WORD keyCode)
{
  return event.EventType == KEY_EVENT
    && !event.Event.KeyEvent.bKeyDown
    && event.Event.KeyEvent.wVirtualKeyCode == keyCode;
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
  DWORD                      FdOutModeOld = 0;
  DWORD                      FdOutModeNew = 0;
  DWORD                      FdInModeOld = 0;
  DWORD                      FdInModeNew = 0;
  INPUT_RECORD               InputEvent = {};
  std::wstring               InputBuffer = {};

  Shell();
  virtual ~Shell();

  USHORT Width();
  USHORT Height();

  VOID Poll(std::vector<View*>& views, SIZE_T& selectedView);
  VOID Read(View* view);

  VOID Clear(USHORT x, USHORT y, USHORT w, USHORT h);
  VOID Frame(USHORT x, USHORT y, USHORT w, USHORT h);

  VOID Text(USHORT x, USHORT y, PCHAR str);
  VOID TextW(USHORT x, USHORT y, PWCHAR str);
};

#endif
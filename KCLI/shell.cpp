#include "shell.h"

using namespace std;

Shell::Shell()
{
  StdOut = GetStdHandle(STD_OUTPUT_HANDLE);
  StdIn = GetStdHandle(STD_INPUT_HANDLE);
  GetConsoleScreenBufferInfo(StdOut, &CsbInfo);
  AttrOld = CsbInfo.wAttributes;
  ScreenWidth = NormalizeMul2((USHORT)CsbInfo.srWindow.Right);
  ScreenHeight = NormalizeMul2((USHORT)CsbInfo.srWindow.Bottom);
  GetConsoleCursorInfo(StdOut, &CcInfoOld);
  CcInfoNew = CcInfoOld;
  CcInfoNew.bVisible = 0;
  SetConsoleCursorInfo(StdOut, &CcInfoNew);
  GetConsoleMode(StdIn, &FdModeOld);
  FdModeNew = FdModeOld | (ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
  SetConsoleMode(StdIn, FdModeNew);
}
Shell::~Shell()
{
  SetConsoleMode(StdIn, FdModeOld);
  GetConsoleCursorInfo(StdOut, &CcInfoOld);
  SetConsoleTextAttribute(StdOut, AttrOld);
}

USHORT Shell::Width()
{
  return ScreenWidth;
}
USHORT Shell::Height()
{
  return ScreenHeight;
}

VOID Shell::Poll(State& state, SIZE_T& selectedView, SIZE_T numViews)
{
  DWORD read = 0;
  ReadConsoleInput(StdIn, &InputEvent, 1, &read);
  if (read)
  {
    switch (InputEvent.EventType)
    {
      case WINDOW_BUFFER_SIZE_EVENT:
      {
        GetConsoleScreenBufferInfo(StdOut, &CsbInfo);
        ScreenWidth = NormalizeMul2((USHORT)CsbInfo.srWindow.Right);
        ScreenHeight = NormalizeMul2((USHORT)CsbInfo.srWindow.Bottom);
        SetConsoleCursorInfo(StdOut, &CcInfoNew);
        state = KCLI_INVALIDATE;
        break;
      }
      case KEY_EVENT:
      {
        if (InputEvent.Event.KeyEvent.bKeyDown)
        {
          switch (InputEvent.Event.KeyEvent.wVirtualKeyCode)
          {
            case VK_TAB:
            {
              state = KCLI_READ;
              break;
            }
            case VK_LEFT:
            {
              selectedView--;
              selectedView = selectedView % numViews;
              break;
            }
            case VK_RIGHT:
            {
              selectedView++;
              selectedView = selectedView % numViews;
              break;
            }
            case VK_UP:
            {
              selectedView++;
              selectedView = selectedView % numViews;
              break;
            }
            case VK_DOWN:
            {
              selectedView--;
              selectedView = selectedView % numViews;
              break;
            }
          }
        }
        break;
      }
    }
  }
}
VOID Shell::Read(State& state, View* view)
{
  CONSOLE_READCONSOLE_CONTROL ctrl;
  ctrl.nLength = sizeof(CONSOLE_READCONSOLE_CONTROL);
  ctrl.nInitialChars = 0;
  ctrl.dwCtrlWakeupMask = 0x0A;
  ctrl.dwControlKeyState = 0;
  Clear(view->X + 1, view->Y + view->H - 2, view->W - 2, 1);
  wstring xStr = to_wstring(1 + view->X + 1);
  wstring yStr = to_wstring(1 + view->Y + view->H - 2);
  wstring vtSetPos = L"\033[" + yStr + L";" + xStr + L"f>";
  WriteConsole(StdOut, &vtSetPos[0], (ULONG)vtSetPos.size(), NULL, NULL);
  ULONG read = 0;
  ReadConsole(StdIn, InputBuffer, 1023, &read, NULL);
  state = KCLI_IDLE;
}

VOID Shell::Clear(USHORT x, USHORT y, USHORT w, USHORT h)
{
  PCHAR_INFO charInfos = (PCHAR_INFO)malloc(sizeof(CHAR_INFO) * w * h);
  memset(charInfos, 0, sizeof(CHAR_INFO) * w * h);
  for (SIZE_T i = 0; i < (w * h); ++i)
  {
    charInfos->Char.UnicodeChar = L' ';
  }
  SMALL_RECT rect{ (SHORT)x, (SHORT)y, (SHORT)(x + w), (SHORT)(y + h) };
  WriteConsoleOutput(
    StdOut,
    charInfos,
    COORD{ (SHORT)w, (SHORT)h },
    COORD{ 0, 0 },
    &rect
  );
  free(charInfos);
}
VOID Shell::Frame(USHORT x, USHORT y, USHORT w, USHORT h)
{
  PCHAR_INFO charInfos = (PCHAR_INFO)malloc(sizeof(CHAR_INFO) * w * h);
  memset(charInfos, 0, sizeof(CHAR_INFO) * w * h);
  for (SIZE_T i = 0; i < (w * h); ++i)
  {
    charInfos[i].Char.UnicodeChar = L' ';
  }
  for (USHORT i{}; i < w; ++i)
  {
    for (USHORT j{}; j < h; ++j)
    {
      ULONG idx{ (ULONG)i + (ULONG)j * (ULONG)w };
      charInfos[idx].Attributes = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
      if (i == 0 || i == w - 1)     charInfos[idx].Char.UnicodeChar = L'│';
      if (j == 0 || j == h - 1)     charInfos[idx].Char.UnicodeChar = L'─';
      if (i == 0 && j == 0)         charInfos[idx].Char.UnicodeChar = L'┌';
      if (i == 0 && j == h - 1)     charInfos[idx].Char.UnicodeChar = L'└';
      if (i == w - 1 && j == 0)     charInfos[idx].Char.UnicodeChar = L'┐';
      if (i == w - 1 && j == h - 1) charInfos[idx].Char.UnicodeChar = L'┘';
    }
  }
  SMALL_RECT rect{ (SHORT)x, (SHORT)y, (SHORT)(x + w), (SHORT)(y + h) };
  WriteConsoleOutput(
    StdOut,
    charInfos,
    COORD{ (SHORT)w, (SHORT)h },
    COORD{ 0, 0 },
    &rect
  );
  free(charInfos);
}

VOID Shell::Text(USHORT x, USHORT y, PCHAR str)
{
  SIZE_T strLen = strlen(str);
  PCHAR_INFO charInfos = (PCHAR_INFO)malloc(sizeof(CHAR_INFO) * strLen);
  memset(charInfos, 0, sizeof(CHAR_INFO) * strLen);
  for (SIZE_T i = 0; i < strLen; ++i)
  {
    charInfos[i].Char.AsciiChar = str[i];
    charInfos[i].Attributes = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
  }
  SMALL_RECT rect{ (SHORT)x, (SHORT)y, (SHORT)(x + strLen), (SHORT)y };
  WriteConsoleOutput(
    StdOut,
    charInfos,
    COORD{ (SHORT)strLen, 1 },
    COORD{ 0, 0 },
    &rect
  );
  free(charInfos);
}
VOID Shell::TextW(USHORT x, USHORT y, PWCHAR str)
{
  SIZE_T strLen = wcslen(str);
  PCHAR_INFO charInfos = (PCHAR_INFO)malloc(sizeof(CHAR_INFO) * strLen);
  memset(charInfos, 0, sizeof(CHAR_INFO) * strLen);
  for (SIZE_T i = 0; i < strLen; ++i)
  {
    charInfos[i].Char.UnicodeChar = str[i];
    charInfos[i].Attributes = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
  }
  SMALL_RECT rect{ (SHORT)x, (SHORT)y, (SHORT)(x + strLen), (SHORT)y };
  WriteConsoleOutput(
    StdOut,
    charInfos,
    COORD{ (SHORT)strLen, 1 },
    COORD{ 0, 0 },
    &rect
  );
  free(charInfos);
}
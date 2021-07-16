#include "shell.h"

Shell::Shell()
{
  StdOut = GetStdHandle(STD_OUTPUT_HANDLE);
  StdIn = GetStdHandle(STD_INPUT_HANDLE);
  GetConsoleScreenBufferInfo(StdOut, &CsbInfo);
  AttrOld = CsbInfo.wAttributes;
  ScreenWidth = (USHORT)CsbInfo.srWindow.Right;
  ScreenHeight = (USHORT)CsbInfo.srWindow.Bottom;
  GetConsoleCursorInfo(StdOut, &CcInfoOld);
  CcInfoNew = CcInfoOld;
  CcInfoNew.bVisible = 0;
  SetConsoleCursorInfo(StdOut, &CcInfoNew);
  GetConsoleMode(StdIn, &FdModeOld);
  FdModeNew = FdModeOld & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT);
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

VOID Shell::Poll()
{
  DWORD read = 0;
  ReadConsoleInput(StdIn, &InputEvent, 1, &read);
  switch (InputEvent.EventType)
  {
    case WINDOW_BUFFER_SIZE_EVENT:
    {
      SetConsoleCursorInfo(StdOut, &CcInfoNew);
      ScreenWidth = (USHORT)InputEvent.Event.WindowBufferSizeEvent.dwSize.X;
      ScreenHeight = (USHORT)InputEvent.Event.WindowBufferSizeEvent.dwSize.Y;
      break;
    }
    case KEY_EVENT:
    {
      if (InputEvent.Event.KeyEvent.bKeyDown)
      {
        switch (InputEvent.Event.KeyEvent.wVirtualKeyCode)
        {
          case VK_LEFT:  break;
          case VK_RIGHT: break;
          case VK_UP:    break;
          case VK_DOWN:  break;
        }
      }
      break;
    }
  }
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
VOID Shell::Text(USHORT x, USHORT y, PCWCHAR str)
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
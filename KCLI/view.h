#ifndef _VIEW_H
#define _VIEW_H

#include "global.h"
#include "shell.h"
#include "ioctrl.h"

enum RenderMode
{
  Idle,
  Invalidate,
};

struct View
{
  std::wstring Legend;

  View(std::wstring const& legend);
  virtual ~View() = default;

  virtual void Render(USHORT x, USHORT y, USHORT w, USHORT h, Shell* shell);
};

struct Memory : View
{
  REQ_MEMORY_READ Request{};

  Memory(std::wstring const& legend);

  virtual void Fetch(HANDLE device, std::wstring const& imageName, ULONG64 base, ULONG offset, SIZE_T size);
  void Render(USHORT x, USHORT y, USHORT w, USHORT h, Shell* shell) override;
};
struct Scanner : View
{
  std::vector<std::uint8_t> currBytes;
  std::vector<std::uint8_t> prevBytes;

  Scanner(std::wstring const& legend);

  void Fetch(HANDLE device);
  void Render(USHORT x, USHORT y, USHORT w, USHORT h, Shell* shell) override;
};
struct Debugger : View
{
  Debugger(std::wstring const& legend);

  void Fetch(HANDLE device);
  void Render(USHORT x, USHORT y, USHORT w, USHORT h, Shell* shell) override;
};

#endif
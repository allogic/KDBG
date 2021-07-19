#ifndef _VIEW_H
#define _VIEW_H

#include "global.h"
#include "ioctrl.h"

/*
* Forward decls.
*/

struct Shell;

/*
* View interface.
*/

struct View
{
  HANDLE ScreenBuffer = INVALID_HANDLE_VALUE;
  Shell* Console = nullptr;
  ULONG Id = 0;
  USHORT X = 0;
  USHORT Y = 0;
  USHORT W = 0;
  USHORT H = 0;
  std::wstring Legend = L"";

  View(Shell* console, ULONG id, USHORT x, USHORT y, USHORT w, USHORT h, std::wstring const& legend);
  virtual ~View() = default;

  virtual void Update();
  virtual void Render();
  virtual void Read(State& state);
};

/*
* Views.
*/

struct Module : View
{
  REQ_PROCESS_MODULES Request;

  Module(Shell* shell, ULONG id, USHORT x, USHORT y, USHORT w, USHORT h, std::wstring const& legend);

  void Update() override;
  virtual void Fetch(HANDLE device, SIZE_T size);
  void Render() override;
};
struct Memory : View
{
  REQ_MEMORY_READ Request;

  Memory(Shell* shell, ULONG id, USHORT x, USHORT y, USHORT w, USHORT h, std::wstring const& legend);

  void Update() override;
  virtual void Fetch(HANDLE device, std::wstring const& imageName, ULONG offset, SIZE_T size);
  void Render() override;
};
struct Scanner : View
{
  std::vector<std::uint8_t> currBytes;
  std::vector<std::uint8_t> prevBytes;

  Scanner(Shell* shell, ULONG id, USHORT x, USHORT y, USHORT w, USHORT h, std::wstring const& legend);

  void Update() override;
  void Fetch(HANDLE device);
  void Render() override;
};
struct Debugger : View
{
  REQ_MEMORY_READ Request;
  csh             CsHandle;

  Debugger(Shell* shell, ULONG id, USHORT x, USHORT y, USHORT w, USHORT h, std::wstring const& legend);
  virtual ~Debugger();

  void Update() override;
  void Fetch(HANDLE device, std::wstring const& imageName, ULONG offset, SIZE_T size);
  void Render() override;
};

#endif
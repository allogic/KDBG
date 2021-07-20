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
  HANDLE Device = INVALID_HANDLE_VALUE;
  Shell* Console = nullptr;
  ULONG Id = 0;
  USHORT X = 0;
  USHORT Y = 0;
  USHORT W = 0;
  USHORT H = 0;
  std::wstring Legend = L"";

  View(HANDLE device, Shell* console, ULONG id, USHORT x, USHORT y, USHORT w, USHORT h, std::wstring const& legend);
  virtual ~View() = default;

  virtual void UpdateLayout();
  virtual void Fetch();
  virtual void Render();
  virtual void Event(INPUT_RECORD& event);
  virtual void Command(std::wstring const& command);
};

/*
* Views.
*/

struct Module : View
{
  REQ_PROCESS_MODULES Request;
  SIZE_T Size;

  Module(
    HANDLE device,
    Shell* shell,
    ULONG id,
    USHORT x,
    USHORT y,
    USHORT w,
    USHORT h,
    std::wstring const& legend,
    SIZE_T size
  );

  void UpdateLayout() override;
  void Fetch() override;
  void Render() override;
};
struct Memory : View
{
  REQ_MEMORY_READ Request;
  SIZE_T Size;
  ULONG Offset;
  std::wstring ImageName;

  Memory(
    HANDLE device,
    Shell* shell,
    ULONG id,
    USHORT x,
    USHORT y,
    USHORT w,
    USHORT h,
    std::wstring const& legend,
    SIZE_T size,
    ULONG offset,
    std::wstring const& imageName
  );

  void UpdateLayout() override;
  void Fetch() override;
  void Render() override;
  void Event(INPUT_RECORD& event) override;
  void Command(std::wstring const& command) override;
};
struct Scanner : View
{
  std::vector<std::uint8_t> currBytes;
  std::vector<std::uint8_t> prevBytes;

  Scanner(
    HANDLE device,
    Shell* shell,
    ULONG id,
    USHORT x,
    USHORT y,
    USHORT w,
    USHORT h,
    std::wstring const& legend
  );

  void UpdateLayout() override;
  void Fetch() override;
  void Render() override;

  void Event(INPUT_RECORD& event) override;
  void Scanner::Command(std::wstring const& command) override;
};
struct Debugger : View
{
  REQ_MEMORY_READ Request;
  csh CsHandle;
  SIZE_T Size;
  ULONG Offset;
  std::wstring ImageName;

  Debugger(
    HANDLE device,
    Shell* shell,
    ULONG id,
    USHORT x,
    USHORT y,
    USHORT w,
    USHORT h,
    std::wstring const& legend,
    SIZE_T size,
    ULONG offset,
    std::wstring const& imageName
  );
  virtual ~Debugger();

  void UpdateLayout() override;
  void Fetch() override;
  void Render() override;
  void Event(INPUT_RECORD& event) override;
  void Command(std::wstring const& command) override;
};

#endif
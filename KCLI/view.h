#ifndef _VIEW_H
#define _VIEW_H

#include "global.h"
#include "common.h"
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
  HANDLE Device = INVALID_HANDLE_VALUE;
  Shell* Console = nullptr;
  ULONG Id = 0;
  USHORT X = 0;
  USHORT Y = 0;
  USHORT W = 0;
  USHORT H = 0;
  std::wstring Legend = L"";

  View(HANDLE device, Shell* console, ULONG id, USHORT x, USHORT y, USHORT w, USHORT h, std::wstring const& legend);
  virtual ~View();

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
  //std::vector<MODULE> Modules = {};
  SIZE_T Size = 0;

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
struct Thread : View
{
  //std::vector<THREAD> Threads = {};
  SIZE_T Size = 0;

  Thread(
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

  void Event(INPUT_RECORD& event) override;
  void Command(std::wstring const& command) override;
};
struct Memory : View
{
  PVOID Request;
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
  void Command(std::wstring const& command) override;
};
struct Debugger : View
{
  std::vector<BYTE> Bytes = {};
  csh CsHandle = 0;
  SIZE_T Size = 0;
  ULONG Offset = 0;
  std::wstring ImageName = L"";

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
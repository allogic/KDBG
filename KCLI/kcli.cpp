#include "global.h"
#include "shell.h"
#include "view.h"

// TODO: create view serializer via JSON
// TODO: finish event handling
// TODO: fix text input max length
// TODO: start using custom primitive typedefs for std lib
// TODO: implement PDB mapping

using namespace std;

/*
* View utilities.
*/

string IndexToName(uint32_t index)
{
  static map<uint32_t, string> map
  {
    { 0, "module" },
    { 1, "memory" },
    { 2, "scanner" },
    { 3, "debugger" },
  };
  return map[index];
}
uint32_t NameToIndex(string name)
{
  static map<string, uint32_t> map
  {
    { "module", 0 },
    { "memory", 1 },
    { "scanner", 2 },
    { "debugger", 3 },
  };
  return map[name];
}

/*
* Theeee driver.
*/

HANDLE Device = INVALID_HANDLE_VALUE;

/*
* Entry point.
*/

int32_t wmain(int32_t argc, wchar_t* argv[])
{
  Device = CreateFileA("\\\\.\\KMOD", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
  if (Device == INVALID_HANDLE_VALUE)
  {
    KCLI_LOG_ERROR("Device connection cannot be established\n");
  }
  else
  {
    REQ_PROCESS_ATTACH reqest;
    reqest.In.Pid = wcstoul(argv[1], nullptr, 10);
    if (DeviceIoControl(Device, KMOD_REQ_PROCESS_ATTACH, &reqest, sizeof(reqest), &reqest, sizeof(reqest), nullptr, nullptr))
    {
      Shell shell;
      USHORT thirdWidth = (USHORT)(shell.Width() / 3);
      USHORT halfHeight = (USHORT)(shell.Height() / 2);
      Module moduleView{ Device, &shell, 0, 0, 0, 0, 0, L"Modules", 32 };
      Thread threadView{ Device, &shell, 1, 0, 0, 0, 0, L"Threads", 32 };
      Memory memoryView{ Device, &shell, 2, 0, 0, 0, 0, L"Memory", 512, 0, L"kernel32.dll" };
      Scanner scannerView{ Device, &shell, 3, 0, 0, 0, 0, L"Scanner" };
      Debugger debuggerView{ Device, &shell, 4, 0, 0, 0, 0, L"Debugger", 512, 0, L"taskmgr.exe" };
      vector<View*> views
      {
        &moduleView,
        &threadView,
        &memoryView,
        &scannerView,
        &debuggerView,
      };
      for (View* view : views)
      {
        view->Fetch();
        view->UpdateLayout();
        view->Render();
      }
      SIZE_T selectedView = NameToIndex("scanner");
      State state = KCLI_CTRL_MODE;
      while (true)
      {
        switch (state)
        {
          case KCLI_CTRL_MODE:
          {
            shell.Poll(views, selectedView);
            if (KeyDown(shell.InputEvent, VK_TAB))
            {
              state = KCLI_CMD_MODE;
            }
            break;
          }
          case KCLI_CMD_MODE:
          {
            shell.Read(views[selectedView]);
            views[selectedView]->Command(shell.InputBuffer);
            state = KCLI_CTRL_MODE;
            break;
          }
        }
      };
      for (View*& view : views)
      {
        delete view;
        view = nullptr;
      }
    }
  }
  CloseHandle(Device);
  return 0;
}
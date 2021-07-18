#include "global.h"
#include "shell.h"
#include "view.h"

// TODO: create view serializer via JSON
// TODO: finish event handling
// TODO: create text input window
// TODO: create MDL for copy module buffer
// TODO: support buffer scrolling for selected window

using namespace std;

/*
* Entry point.
*/

int32_t wmain(int32_t argc, wchar_t* argv[])
{
  HANDLE device = CreateFileA("\\\\.\\KMOD", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
  if (device == INVALID_HANDLE_VALUE)
  {
    KCLI_LOG_ERROR("Device connection cannot be established\n");
  }
  else
  {
    REQ_PROCESS_ATTACH reqest;
    reqest.In.Pid = wcstoul(argv[1], nullptr, 10);
    if (DeviceIoControl(device, KMOD_REQ_PROCESS_ATTACH, &reqest, sizeof(reqest), &reqest, sizeof(reqest), nullptr, nullptr))
    {
      Shell shell;
      map<string, View*> views
      {
        { "module", new Module{ L"Module" } },
        { "memory", new Memory{ L"Memory" } },
        { "scanner", new Scanner{ L"Scanner" } },
        { "debugger", new Debugger{ L"Debugger" } },
      };
      RenderMode mode = Fetch;
      while (true)
      {
        switch (mode)
        {
          case Idle:
          {
            break;
          }
          case Fetch:
          {
            ((Module*)views["module"])->Fetch(device, 8);
            ((Memory*)views["memory"])->Fetch(device, L"deadspace3.exe", 0, 512);
            ((Scanner*)views["scanner"])->Fetch(device);
            ((Debugger*)views["debugger"])->Fetch(device, L"deadspace3.exe", 0, 512);
            mode = Invalidate;
            break;
          }
          case Invalidate:
          {
            shell.Clear(0, 0, shell.Width() + 1, shell.Height() + 1);
            USHORT thirdWidth = (USHORT)(shell.Width() / 3);
            USHORT halfHeight = (USHORT)(shell.Height() / 2);
            //views["module"]->Render(0, 0, shell.Width(), shell.Height(), &shell);
            views["memory"]->Render(
              thirdWidth,
              halfHeight,
              shell.Width() - thirdWidth,
              halfHeight,
              &shell
            );
            views["scanner"]->Render(
              0,
              0,
              thirdWidth,
              shell.Height(),
              &shell
            );
            views["debugger"]->Render(
              thirdWidth,
              0,
              shell.Width() - thirdWidth,
              shell.Height() - halfHeight,
              &shell
            );
            mode = Idle;
            break;
          }
        }
        shell.Poll(mode);
      };
      for (auto& [name, view] : views)
      {
        delete view;
        view = nullptr;
      }
    }
  }
}
#include "global.h"
#include "shell.h"
#include "view.h"

// TODO: create view serializer via JSON
// TODO: finish event handling
// TODO: create text input window
// TODO: create MDL for copy module buffer
// TODO: support buffer scrolling for selected window
// TODO: fix text input max length

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
* Entry point.
*/

int32_t wmain(int32_t argc, wchar_t* argv[])
{
  //HANDLE device = CreateFileA("\\\\.\\KMOD", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
  //if (device == INVALID_HANDLE_VALUE)
  //{
  //  KCLI_LOG_ERROR("Device connection cannot be established\n");
  //}
  //else
  //{
    //REQ_PROCESS_ATTACH reqest;
    //reqest.In.Pid = wcstoul(argv[1], nullptr, 10);
    //if (DeviceIoControl(device, KMOD_REQ_PROCESS_ATTACH, &reqest, sizeof(reqest), &reqest, sizeof(reqest), nullptr, nullptr))
    //{
      Shell shell;
      USHORT thirdWidth = (USHORT)(shell.Width() / 3);
      USHORT halfHeight = (USHORT)(shell.Height() / 2);
      vector<View*> views
      {
        //new Module{ &shell, 0, 0, 0, shell.Width(), shell.Height(), L"Module" },
        new Memory{ &shell, 0, thirdWidth, halfHeight, (USHORT)(shell.Width() - thirdWidth), halfHeight, L"Memory" },
        new Scanner{ &shell, 1, 0, 0, thirdWidth, shell.Height(), L"Scanner" },
        new Debugger{ &shell, 2, thirdWidth, 0, (USHORT)(shell.Width() - thirdWidth), (USHORT)(shell.Height() - halfHeight), L"Debugger" },
      };
      SIZE_T selectedView = NameToIndex("scanner");
      State state = KCLI_FETCH;
      while (true)
      {
        switch (state)
        {
          case KCLI_IDLE:
          {
            break;
          }
          case KCLI_FETCH:
          {
            //((Module*)views["module"])->Fetch(device, 8);
            //((Memory*)views["memory"])->Fetch(device, L"deadspace3.exe", 0, 512);
            //((Scanner*)views["scanner"])->Fetch(device);
            //((Debugger*)views["debugger"])->Fetch(device, L"deadspace3.exe", 0, 512);
            state = KCLI_INVALIDATE;
            break;
          }
          case KCLI_INVALIDATE:
          {
            shell.Clear(0, 0, shell.Width() + 1, shell.Height() + 1);
            for (View* view : views)
            {
              view->Update();
              view->Render();
            }
            state = KCLI_IDLE;
            break;
          }
          case KCLI_READ:
          {
            views[selectedView]->Read(state);
            break;
          }
        }
        shell.Poll(state, selectedView, views.size());
      };
      for (View*& view : views)
      {
        delete view;
        view = nullptr;
      }
    //}
  //}
  return 0;
}
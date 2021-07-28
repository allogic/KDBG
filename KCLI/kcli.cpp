#include "global.h"
#include "shell.h"
#include "socket.h"
#include "view.h"
#include "util.h"

// TODO: create view serializer via JSON
// TODO: finish event handling
// TODO: fix text input max length
// TODO: start using windows primitive typedefs for everything
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
* Communication socket.
*/

WSADATA WsaData = {};
SOCKET Socket = INVALID_SOCKET;
PADDRINFOA Address = NULL;

/*
* Entry point.
*/

int32_t wmain(int32_t argc, wchar_t* argv[])
{
  WSAStartup(MAKEWORD(2, 2), &WsaData);
  ADDRINFOA hints = {};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  if (getaddrinfo(&Utf16ToUtf8(argv[1])[0], "9095", &hints, &Address) == 0)
  {
    Socket = socket(Address->ai_family, Address->ai_socktype, Address->ai_protocol);
    if (Socket != INVALID_SOCKET)
    {
      KC_LOG_INFO("Socket found\n");
      if (connect(Socket, Address->ai_addr, (INT)Address->ai_addrlen) == 0)
      {
        KC_LOG_INFO("Connected\n");
        ULONG size = 1024;
        CHAR buffer[1024] = {};
        if (send(Socket, buffer, size, 0) == 0)
        {
          KC_LOG_INFO("Sent %u bytes\n", size);
        }

        //INT result = 0;
        //do
        //{
        //  KC_LOG_INFO("Receiving..\n");
        //  result = recv(Socket, buffer, sizeof(buffer), 0);
        //  KC_LOG_INFO("Received\n");
        //  if (result > 0)
        //  {
        //    KC_LOG_INFO("Received %llu bytes\n", sizeof(buffer));
        //  }
        //  else if (result == 0)
        //  {
        //    KC_LOG_INFO("Connection closed\n");
        //  }
        //  else
        //  {
        //    KC_LOG_INFO("Receive failed with error %d\n", WSAGetLastError());
        //  }
        //}
        //while (result > 0);
      }
      closesocket(Socket);
    }
  }
  WSACleanup();
  return 0;
  Shell shell;
  USHORT thirdWidth = (USHORT)(shell.Width() / 3);
  USHORT halfHeight = (USHORT)(shell.Height() / 2);
  Module moduleView{ NULL, &shell, 0, 0, 0, 0, 0, L"Modules", 32 };
  Thread threadView{ NULL, &shell, 1, 0, 0, 0, 0, L"Threads", 32 };
  Memory memoryView{ NULL, &shell, 2, 0, 0, 0, 0, L"Memory", 512, 0, L"kernel32.dll" };
  Scanner scannerView{ NULL, &shell, 3, 0, 0, 0, 0, L"Scanner" };
  Debugger debuggerView{ NULL, &shell, 4, 0, 0, 0, 0, L"Debugger", 512, 0, L"taskmgr.exe" };
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
    //view->Fetch();
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
  return 0;
}
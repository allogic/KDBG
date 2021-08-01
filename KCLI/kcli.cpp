#include "global.h"
#include "common.h"
#include "ioctrl.h"
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
* Request/Response handlers.
*/

VOID KcReadMemoryProcess(SOCKET socket, ULONG pid, PWCHAR imageName, ULONG offset, ULONG size)
{
  CHAR ctrl = (CHAR)KM_READ_MEMORY_PROCESS;
  if (send(socket, &ctrl, sizeof(CHAR), 0) > 0)
  {
    READ_MEMORY_PROCESS request = {};
    request.Pid = pid;
    memcpy(request.ImageName, imageName, wcslen(imageName));
    request.Offset = offset;
    request.Size = size;
    if (send(socket, (PCHAR)&request, sizeof(request), 0) > 0)
    {
      KC_LOG_INFO("Sent read request\n");
    }
  }
}

VOID KcWriteMemoryProcess(SOCKET socket, ULONG pid, PWCHAR imageName, ULONG offset, ULONG size, PCHAR bytes)
{
  CHAR ctrl = (CHAR)KM_WRITE_MEMORY_PROCESS;
  if (send(socket, &ctrl, sizeof(CHAR), 0) > 0)
  {
    WRITE_MEMORY_PROCESS request = {};
    request.Pid = pid;
    memcpy(request.ImageName, imageName, wcslen(imageName));
    request.Offset = offset;
    request.Size = size;
    memcpy(request.Bytes, bytes, strlen(bytes));
    if (send(socket, (PCHAR)&request, sizeof(request), 0) > 0)
    {
      KC_LOG_INFO("Sent write request\n");
    }
  }
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
  hints.ai_family = AF_INET;
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
        KcReadMemoryProcess(Socket, 666, L"666.exe", 666, 666);
        //KcWriteMemoryProcess(Socket, 666, L"666.exe", 666, 666, "9090909090");
        while (TRUE)
        {

        }
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
  SIZE_T selectedView = 0;
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
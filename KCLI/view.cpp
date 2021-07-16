#include "view.h"

View::View(std::wstring const& legend)
{
  Legend = legend;
}

void View::Render(USHORT x, USHORT y, USHORT w, USHORT h, Shell* shell)
{
  shell->Frame(x, y, w, h);
  shell->TextW(x + 1, y, Legend.c_str()); 
}

Memory::Memory(std::wstring const& legend)
  : View(legend)
{

}
void Memory::Fetch(HANDLE device, std::wstring const& imageName, ULONG64 base, ULONG offset, SIZE_T size)
{
  Request.Base = base;
  if (Request.Name)
  {
    std::free(Request.Name);
  }
  Request.Name = (PWCHAR)std::malloc(sizeof(WCHAR) * imageName.size());
  std::memcpy(Request.Name, imageName.c_str(), sizeof(WCHAR) * imageName.size());
  Request.Offset = offset;
  Request.Size = size;
  if (Request.Buffer)
  {
    std::free(Request.Buffer);
  }
  Request.Buffer = std::malloc(sizeof(PBYTE) * size);
  LOG_INFO("Sending request");
  DeviceIoControl(device, KMOD_REQ_MEMORY_READ, &Request, sizeof(Request), &Request, sizeof(Request), NULL, NULL);
  LOG_INFO("Sent request");
}
void Memory::Render(USHORT x, USHORT y, USHORT w, USHORT h, Shell* shell)
{
  View::Render(x, y, w, h, shell);
  for (USHORT i = 1; i < (w - 1); ++i)
  {
    // support multiple view modes
    shell->Char(x + i, 0, ((PCHAR)Request.Buffer)[i]);
  }
}

Scanner::Scanner(std::wstring const& legend)
  : View(legend)
{

}
void Scanner::Fetch(HANDLE device)
{

}
void Scanner::Render(USHORT x, USHORT y, USHORT w, USHORT h, Shell* shell)
{
  View::Render(x, y, w, h, shell);
}

Debugger::Debugger(std::wstring const& legend)
  : View(legend)
{

}
void Debugger::Fetch(HANDLE device)
{

}
void Debugger::Render(USHORT x, USHORT y, USHORT w, USHORT h, Shell* shell)
{
  View::Render(x, y, w, h, shell);
}
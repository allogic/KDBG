#include "view.h"
#include "shell.h"
#include "util.h"

using namespace std;

View::View(Shell* console, ULONG id, USHORT x, USHORT y, USHORT w, USHORT h, wstring const& legend)
  : Console{ console }
  , Id{ id }
  , X{ x }
  , Y{ y }
  , W{ w }
  , H{ h }
  , Legend{ legend }
{
  ScreenBuffer = CreateConsoleScreenBuffer(GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CONSOLE_TEXTMODE_BUFFER, NULL);
}

void View::Update()
{

}
void View::Render()
{
  Console->Frame(X, Y, W, H);
  Console->TextW(X + 1, Y, &Legend[0]); 
}
void View::Read(State& state)
{
  Console->Read(state, this);
}

Module::Module(Shell* console, ULONG id, USHORT x, USHORT y, USHORT w, USHORT h, wstring const& legend)
  : View(console, id, x, y, w, h, legend)
{

}
void Module::Update()
{
  X = 0;
  Y = 0;
  W = Console->Width();
  H = Console->Height();
}
void Module::Fetch(HANDLE device, SIZE_T size)
{
  Request.In.Size = size;
  Request.Out.Size = size;
  if (Request.Out.Buffer)
  {
    free(Request.Out.Buffer);
  }
  Request.Out.Buffer = malloc(sizeof(MODULE) * size);
  memset(Request.Out.Buffer, 0, sizeof(MODULE) * size);
  for (SIZE_T i = 0; i < Request.In.Size; ++i)
  {
    ((PMODULE)Request.Out.Buffer)[i].Base = 666;
    wcscpy_s(((PMODULE)Request.Out.Buffer)[i].Name, sizeof(WCHAR) * 4, L"Dead");
    ((PMODULE)Request.Out.Buffer)[i].Size = 333;
  }
  DeviceIoControl(device, KMOD_REQ_PROCESS_MODULES, &Request, sizeof(Request), &Request, sizeof(Request), nullptr, nullptr);
}
void Module::Render()
{
  View::Render();
  USHORT xOff = 1;
  USHORT yOff = 1;
  for (SIZE_T i = 0; i < Request.Out.Size; ++i)
  {
    Console->TextW(X + xOff, Y + yOff, &AddressToHexW(((PMODULE)Request.Out.Buffer)[i].Base)[0]);
    xOff += 19;
    Console->TextW(X + xOff, Y + yOff, &ULongToDecW((ULONG)((PMODULE)Request.Out.Buffer)[i].Size)[0]);
    xOff += 19;
    Console->TextW(X + xOff, Y + yOff, ((PMODULE)Request.Out.Buffer)[i].Name);
    xOff = 1;
    yOff += 1;
  }
}

Memory::Memory(Shell* console, ULONG id, USHORT x, USHORT y, USHORT w, USHORT h, wstring const& legend)
  : View(console, id, x, y, w, h, legend)
{

}
void Memory::Update()
{
  USHORT thirdWidth = (USHORT)(Console->Width() / 3);
  USHORT halfHeight = (USHORT)(Console->Height() / 2);
  X = thirdWidth;
  Y = halfHeight;
  W = (USHORT)(Console->Width() - thirdWidth);
  H = halfHeight;
}
void Memory::Fetch(HANDLE device, wstring const& imageName, ULONG offset, SIZE_T size)
{
  if (Request.In.Name)
  {
    free(Request.In.Name);
  }
  Request.In.Name = (PWCHAR)malloc(sizeof(WCHAR) * imageName.size() + 1);
  wmemset(Request.In.Name, 0, imageName.size() + 1);
  wmemcpy(Request.In.Name, imageName.c_str(), imageName.size());
  Request.In.Offset = offset;
  Request.In.Size = size;
  if (Request.Out.Buffer)
  {
    free(Request.Out.Buffer);
  }
  Request.Out.Buffer = malloc(sizeof(PBYTE) * size);
  DeviceIoControl(device, KMOD_REQ_MEMORY_READ, &Request, sizeof(Request), &Request, sizeof(Request), nullptr, nullptr);
}
void Memory::Render()
{
  View::Render();
  USHORT xOff = 1;
  USHORT yOff = 1;
  Console->Text(X + xOff, Y + yOff, &AddressToHex(Request.Out.Base)[0]);
  xOff += 19;
  for (USHORT i = 0; i < Request.In.Size; ++i)
  {
    Console->Text(X + xOff, Y + yOff, &ByteToHex(((PBYTE)Request.Out.Buffer)[i])[0]);
    xOff += 3;
    if (xOff >= (W - 2))
    {
      yOff += 1;
      if (yOff >= (H - 1))
      {
        break;
      }
      xOff = 1;
      Console->Text(X + xOff, Y + yOff, &AddressToHex(Request.Out.Base + i)[0]);
      xOff += 19;
    }
  }
}

Scanner::Scanner(Shell* console, ULONG id, USHORT x, USHORT y, USHORT w, USHORT h, wstring const& legend)
  : View(console, id, x, y, w, h, legend)
{

}
void Scanner::Update()
{
  USHORT thirdWidth = (USHORT)(Console->Width() / 3);
  USHORT halfHeight = (USHORT)(Console->Height() / 2);
  X = 0;
  Y = 0;
  W = thirdWidth;
  H = Console->Height();
}
void Scanner::Fetch(HANDLE device)
{

}
void Scanner::Render()
{
  View::Render();
}

Debugger::Debugger(Shell* console, ULONG id, USHORT x, USHORT y, USHORT w, USHORT h, wstring const& legend)
  : View(console, id, x, y, w, h, legend)
{
  cs_open(CS_ARCH_X86, CS_MODE_64, &CsHandle);
}
Debugger::~Debugger()
{
  cs_close(&CsHandle);
}
void Debugger::Update()
{
  USHORT thirdWidth = (USHORT)(Console->Width() / 3);
  USHORT halfHeight = (USHORT)(Console->Height() / 2);
  X = thirdWidth;
  Y = 0;
  W = (USHORT)(Console->Width() - thirdWidth);
  H = (USHORT)(Console->Height() - halfHeight);
}
void Debugger::Fetch(HANDLE device, wstring const& imageName, ULONG offset, SIZE_T size)
{
  if (Request.In.Name)
  {
    free(Request.In.Name);
  }
  Request.In.Name = (PWCHAR)malloc(sizeof(WCHAR) * imageName.size() + 1);
  wmemset(Request.In.Name, 0, imageName.size() + 1);
  wmemcpy(Request.In.Name, imageName.c_str(), imageName.size());
  Request.In.Offset = offset;
  Request.In.Size = size;
  if (Request.Out.Buffer)
  {
    free(Request.Out.Buffer);
  }
  Request.Out.Buffer = malloc(sizeof(PBYTE) * size);
  DeviceIoControl(device, KMOD_REQ_MEMORY_READ, &Request, sizeof(Request), &Request, sizeof(Request), nullptr, nullptr);
}
void Debugger::Render()
{
  View::Render();
  cs_insn* instructions = nullptr;
  SIZE_T numInstructions = cs_disasm(CsHandle, (PBYTE)Request.Out.Buffer, Request.In.Size, Request.Out.Base, 0, &instructions);
  USHORT xOff = 1;
  USHORT yOff = 1;
  if (numInstructions)
  {
    for (SIZE_T i = 0; i < numInstructions; ++i)
    {
      Console->Text(X + xOff, Y + yOff, &AddressToHex(instructions[i].address)[0]);
      xOff += 19;
      for (BYTE j = 0; j < 10; ++j)
      {
        if (j < instructions[i].size)
        {
          Console->Text(X + xOff, Y + yOff, &ByteToHex(instructions[i].bytes[j])[0]);
        }
        else
        {
          Console->Text(X + xOff, Y + yOff, "..");
        }
        xOff += 3;
      }
      Console->Text(X + xOff, Y + yOff, instructions[i].mnemonic);
      xOff += 5;
      Console->Text(X + xOff, Y + yOff, instructions[i].op_str);
      xOff = 1;
      yOff += 1;
    }
  }
  cs_free(instructions, numInstructions);
}
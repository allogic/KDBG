#include "view.h"
#include "util.h"

using namespace std;

View::View(wstring const& legend)
{
  Legend = legend;
}

void View::Render(USHORT x, USHORT y, USHORT w, USHORT h, Shell* shell)
{
  shell->Frame(x, y, w, h);
  shell->TextW(x + 1, y, &Legend[0]); 
}

Module::Module(wstring const& legend)
  : View(legend)
{

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
void Module::Render(USHORT x, USHORT y, USHORT w, USHORT h, Shell* shell)
{
  View::Render(x, y, w, h, shell);
  USHORT xOff = 1;
  USHORT yOff = 1;
  for (SIZE_T i = 0; i < Request.Out.Size; ++i)
  {
    shell->TextW(x + xOff, y + yOff, &AddressToHexW(((PMODULE)Request.Out.Buffer)[i].Base)[0]);
    xOff += 19;
    shell->TextW(x + xOff, y + yOff, &ULongToDecW((ULONG)((PMODULE)Request.Out.Buffer)[i].Size)[0]);
    xOff += 19;
    shell->TextW(x + xOff, y + yOff, ((PMODULE)Request.Out.Buffer)[i].Name);
    xOff = 1;
    yOff += 1;
  }
}

Memory::Memory(wstring const& legend)
  : View(legend)
{

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
void Memory::Render(USHORT x, USHORT y, USHORT w, USHORT h, Shell* shell)
{
  View::Render(x, y, w, h, shell);
  USHORT xOff = 1;
  USHORT yOff = 1;
  shell->Text(x + xOff, y + yOff, &AddressToHex(Request.Out.Base)[0]);
  xOff += 19;
  for (USHORT i = 0; i < Request.In.Size; ++i)
  {
    shell->Text(x + xOff, y + yOff, &ByteToHex(((PBYTE)Request.Out.Buffer)[i])[0]);
    xOff += 3;
    if (xOff >= (w - 2))
    {
      yOff += 1;
      if (yOff >= (h - 1))
      {
        break;
      }
      xOff = 1;
      shell->Text(x + xOff, y + yOff, &AddressToHex(Request.Out.Base + i)[0]);
      xOff += 19;
    }
  }
}

Scanner::Scanner(wstring const& legend)
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

Debugger::Debugger(wstring const& legend)
  : View(legend)
{
  cs_open(CS_ARCH_X86, CS_MODE_64, &CsHandle);
}
Debugger::~Debugger()
{
  cs_close(&CsHandle);
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
void Debugger::Render(USHORT x, USHORT y, USHORT w, USHORT h, Shell* shell)
{
  View::Render(x, y, w, h, shell);
  cs_insn* instructions = nullptr;
  SIZE_T numInstructions = cs_disasm(CsHandle, (PBYTE)Request.Out.Buffer, Request.In.Size, Request.Out.Base, 0, &instructions);
  USHORT xOff = 1;
  USHORT yOff = 1;
  if (numInstructions)
  {
    for (SIZE_T i = 0; i < numInstructions; ++i)
    {
      shell->Text(x + xOff, y + yOff, &AddressToHex(instructions[i].address)[0]);
      xOff += 19;
      for (BYTE j = 0; j < 10; ++j)
      {
        if (j < instructions[i].size)
        {
          shell->Text(x + xOff, y + yOff, &ByteToHex(instructions[i].bytes[j])[0]);
        }
        else
        {
          shell->Text(x + xOff, y + yOff, "..");
        }
        xOff += 3;
      }
      shell->Text(x + xOff, y + yOff, instructions[i].mnemonic);
      xOff += 5;
      shell->Text(x + xOff, y + yOff, instructions[i].op_str);
      xOff = 1;
      yOff += 1;
    }
  }
  cs_free(instructions, numInstructions);
}
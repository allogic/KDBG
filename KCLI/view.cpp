#include "view.h"
#include "shell.h"
#include "util.h"

// TODO: remove request references outside Fetch() function

using namespace std;

View::View(HANDLE device, Shell* console, ULONG id, USHORT x, USHORT y, USHORT w, USHORT h, wstring const& legend)
  : Device{ device }
  , Console{ console }
  , Id{ id }
  , X{ x }
  , Y{ y }
  , W{ w }
  , H{ h }
  , Legend{ legend }
{

}
View::~View()
{

}

void View::UpdateLayout()
{

}
void View::Fetch()
{

}
void View::Render()
{
  Console->Frame(X, Y, W, H);
  Console->TextW(X + 1, Y, &Legend[0]); 
}
void View::Event(INPUT_RECORD& event)
{
  
}
void View::Command(wstring const& command)
{

}

Module::Module(
  HANDLE device,
  Shell* console,
  ULONG id,
  USHORT x,
  USHORT y,
  USHORT w,
  USHORT h,
  wstring const& legend,
  SIZE_T size
)
  : Size{ size }
  , View(device, console, id, x, y, w, h, legend)
{

}
void Module::UpdateLayout()
{
  USHORT w4th = (USHORT)(Console->Width() / 4);
  USHORT hHalf = (USHORT)(Console->Height() / 2);
  X = (USHORT)(Console->Width() - w4th);
  Y = 0;
  W = w4th;
  H = hHalf;
}
void Module::Fetch()
{
  REQ_PROCESS_MODULES request;
  request.In.Size = Size;
  if (request.Out.Buffer)
  {
    free(request.Out.Buffer);
  }
  request.Out.Buffer = malloc(sizeof(MODULE) * KMOD_MAX_MODULES_PROCESS);
  memset(request.Out.Buffer, 0, sizeof(MODULE) * KMOD_MAX_MODULES_PROCESS);
  //DeviceIoControl(Device, KMOD_REQ_PROCESS_MODULES, &request, sizeof(request), &request, sizeof(request), nullptr, nullptr);
  Modules.clear();
  Modules.resize(KMOD_MAX_MODULES_PROCESS);
  memcpy(&Modules[0], request.Out.Buffer, sizeof(MODULE) * KMOD_MAX_MODULES_PROCESS);
}
void Module::Render()
{
  View::Render();
  USHORT xOff = 1;
  USHORT yOff = 1;
  for (MODULE& module : Modules)
  {
    Console->TextW(X + xOff, Y + yOff, &AddressToHexW(module.Base)[0]);
    xOff += 19;
    Console->TextW(X + xOff, Y + yOff, &ULongToDecW((ULONG)module.Size)[0]);
    xOff += 19;
    Console->TextW(X + xOff, Y + yOff, module.Name);
    xOff = 1;
    yOff += 1;
    if (yOff >= (H - 1))
    {
      break;
    }
  }
}

Thread::Thread(
  HANDLE device,
  Shell* console,
  ULONG id,
  USHORT x,
  USHORT y,
  USHORT w,
  USHORT h,
  wstring const& legend,
  SIZE_T size
)
  : Size{ size }
  , View(device, console, id, x, y, w, h, legend)
{

}
void Thread::UpdateLayout()
{
  USHORT w4th = (USHORT)(Console->Width() / 4);
  USHORT hHalf = (USHORT)(Console->Height() / 2);
  X = (USHORT)(Console->Width() - w4th);
  Y = hHalf;
  W = w4th;
  H = hHalf;
}
void Thread::Fetch()
{
  REQ_PROCESS_THREADS request;
  request.In.Size = Size;
  if (request.Out.Buffer)
  {
    free(request.Out.Buffer);
  }
  request.Out.Buffer = malloc(sizeof(THREAD) * KMOD_MAX_THREADS);
  memset(request.Out.Buffer, 0, sizeof(THREAD) * KMOD_MAX_THREADS);
  //DeviceIoControl(Device, KMOD_REQ_PROCESS_THREADS, &request, sizeof(request), &request, sizeof(request), nullptr, nullptr);
  Threads.clear();
  Threads.resize(KMOD_MAX_THREADS);
  memcpy(&Threads[0], request.Out.Buffer, sizeof(THREAD) * KMOD_MAX_THREADS);
}
void Thread::Render()
{
  View::Render();
  USHORT xOff = 1;
  USHORT yOff = 1;
  for (THREAD& thread : Threads)
  {
    Console->TextW(X + xOff, Y + yOff, &ULongToDecW(thread.Tid)[0]);
    xOff += 19;
    Console->TextW(X + xOff, Y + yOff, &ULongToDecW(thread.Pid)[0]);
    xOff += 19;
    yOff += 1;
    if (yOff >= (H - 1))
    {
      break;
    }
  }
}
void Thread::Event(INPUT_RECORD& event)
{

}
void Thread::Command(wstring const& command)
{
  if (wcscmp(L"f", command.data()) == 0)
  {
    Fetch();
  }
}

Memory::Memory(
  HANDLE device,
  Shell* console,
  ULONG id,
  USHORT x,
  USHORT y,
  USHORT w,
  USHORT h,
  wstring const& legend,
  SIZE_T size,
  ULONG offset,
  wstring const& imageName
)
  : ImageName{ imageName }
  , Size{ size }
  , Offset{ offset }
  , View(device, console, id, x, y, w, h, legend)
{

}
void Memory::UpdateLayout()
{
  USHORT w4th = (USHORT)(Console->Width() / 4);
  USHORT hHalf = (USHORT)(Console->Height() / 2);
  X = w4th;
  Y = hHalf;
  W = (USHORT)(Console->Width() - (w4th * 2));
  H = hHalf;
}
void Memory::Fetch()
{
  wmemset(Request.In.Name, 0, ImageName.size());
  wmemcpy(Request.In.Name, ImageName.c_str(), ImageName.size());
  Request.In.Offset = Offset;
  Request.In.Size = Size;
  if (Request.Out.Buffer)
  {
    free(Request.Out.Buffer);
  }
  Request.Out.Buffer = malloc(Size);
  memset(Request.Out.Buffer, 0, Size);
  //DeviceIoControl(Device, KMOD_REQ_MEMORY_READ, &Request, sizeof(Request), &Request, sizeof(Request), nullptr, nullptr);
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
void Memory::Event(INPUT_RECORD& event)
{
  if (KeyDown(event, VK_UP))
  {
    Offset--;
    if (Offset < 0)
    {
      Offset = 0;
    }
    Fetch();
    Render();
  }
  if (KeyDown(event, VK_DOWN))
  {
    Offset++;
    if (Offset >= Request.In.Size)
    {
      Offset = (ULONG)Request.In.Size;
    }
    Fetch();
    Render();
  }
}
void Memory::Command(wstring const& command)
{
  if (wcscmp(L"f", command.data()) == 0)
  {
    Fetch();
    Render();
  }
}

Scanner::Scanner(
  HANDLE device,
  Shell* console,
  ULONG id,
  USHORT x,
  USHORT y,
  USHORT w,
  USHORT h,
  wstring const& legend
)
  : View(device, console, id, x, y, w, h, legend)
{

}
void Scanner::UpdateLayout()
{
  USHORT w4th = (USHORT)(Console->Width() / 4);
  USHORT hHalf = (USHORT)(Console->Height() / 2);
  X = 0;
  Y = 0;
  W = w4th;
  H = Console->Height();
}
void Scanner::Fetch()
{

}
void Scanner::Render()
{
  View::Render();
}
void Scanner::Event(INPUT_RECORD& event)
{

}
void Scanner::Command(wstring const& command)
{
  if (wcscmp(L"f", command.data()) == 0)
  {
    Fetch();
  }
}

Debugger::Debugger(
  HANDLE device,
  Shell* console,
  ULONG id,
  USHORT x,
  USHORT y,
  USHORT w,
  USHORT h,
  wstring const& legend,
  SIZE_T size,
  ULONG offset,
  wstring const& imageName
)
  : ImageName{ imageName }
  , Size{ size }
  , Offset{ offset }
  , View(device, console, id, x, y, w, h, legend)
{
  cs_open(CS_ARCH_X86, CS_MODE_64, &CsHandle);
}
Debugger::~Debugger()
{
  cs_close(&CsHandle);
}
void Debugger::UpdateLayout()
{
  USHORT w4th = (USHORT)(Console->Width() / 4);
  USHORT hHalf = (USHORT)(Console->Height() / 2);
  X = w4th;
  Y = 0;
  W = (USHORT)(Console->Width() - (w4th * 2));
  H = hHalf;
}
void Debugger::Fetch()
{
  REQ_MEMORY_READ request;
  wmemset(request.In.Name, 0, ImageName.size());
  wmemcpy(request.In.Name, ImageName.c_str(), ImageName.size());
  request.In.Offset = Offset;
  request.In.Size = Size;
  if (request.Out.Buffer)
  {
    free(request.Out.Buffer);
  }
  request.Out.Buffer = malloc(Size);
  memset(request.Out.Buffer, 0, Size);
  //DeviceIoControl(Device, KMOD_REQ_MEMORY_READ, &request, sizeof(request), &request, sizeof(request), nullptr, nullptr);
  Bytes.clear();
  Bytes.resize(Size);
  memcpy(Bytes.data(), request.Out.Buffer, Size);
}
void Debugger::Render()
{
  View::Render();
  cs_insn* instructions = nullptr;
  SIZE_T numInstructions = cs_disasm(CsHandle, Bytes.data(), Bytes.size(), 0, 0, &instructions);
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
void Debugger::Event(INPUT_RECORD& event)
{
  if (KeyDown(event, VK_UP))
  {
    Offset--;
    if (Offset < 0)
    {
      Offset = 0;
    }
    Fetch();
    Render();
  }
  if (KeyDown(event, VK_DOWN))
  {
    Offset++;
    if (Offset >= Bytes.size())
    {
      Offset = (ULONG)Bytes.size();
    }
    Fetch();
    Render();
  }
}
void Debugger::Command(wstring const& command)
{
  if (wcscmp(L"f", command.data()) == 0)
  {
    Fetch();
    Render();
  }
}
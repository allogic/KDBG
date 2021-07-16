#include "global.h"
#include "shell.h"
#include "view.h"

/*
* Disassembler.
*/

void DisassembleBytes(std::uint8_t* bytes, std::size_t size, std::size_t offset)
{
  csh csHandle;
  // Open capstone handle
  cs_err error = cs_open(CS_ARCH_X86, CS_MODE_64, &csHandle);
  if (error)
  {
    printf("cs_open\n");
    return;
  }
  // Optain instuctions
  cs_insn* instructions = NULL;
  std::size_t numInstructions = cs_disasm(csHandle, bytes, size, offset, 0, &instructions);
  if (numInstructions)
  {
    // Print assembly instructions
    for (std::size_t i = 0; i < numInstructions; ++i)
    {
      printf("0x%08llX ", (std::uint64_t)instructions[i].address);
      for (std::uint8_t j = 0; j < 23; ++j)
      {
        if (j < instructions[i].size)
          printf("%02X ", instructions[i].bytes[j]);
        else
          printf(".. ");
      }
      printf("%s %s\n", instructions[i].mnemonic, instructions[i].op_str);
    }
  }
  // Cleanup
  cs_free(instructions, numInstructions);
  cs_close(&csHandle);
}

/*
* Entry point.
*/

std::int32_t wmain(std::int32_t argc, wchar_t* argv[])
{
  // Connect to driver
  HANDLE device = CreateFileA("\\\\.\\KMOD", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
  if (device == INVALID_HANDLE_VALUE)
  {
    LOG_ERROR("Device connection cannot be established\n");
  }
  else
  {
    // Attach to process
    REQ_PROCESS_ATTACH reqest{};
    reqest.Pid = wcstoul(argv[1], NULL, 10);
    if (DeviceIoControl(device, KMOD_REQ_PROCESS_ATTACH, &reqest, sizeof(reqest), &reqest, sizeof(reqest), NULL, NULL))
    {
      std::this_thread::sleep_for(std::chrono::milliseconds{ 1000 });
      // User interface
      Shell shell;
      std::map<std::string, View*> views
      {
        { "memory", new Memory{ L"Memory" } },
        { "scanner", new Scanner{ L"Scanner" } },
        { "debugger", new Debugger{ L"Debugger" } },
      };
      RenderMode mode = Invalidate;
      while (true)
      {
        switch (mode)
        {
          case Idle:
          {
            break;
          }
          case Invalidate:
          {
            //shell.Clear(0, 0, shell.Width() + 1, shell.Height() + 1);
            USHORT thirdWidth = (USHORT)(shell.Width() / 3);
            USHORT halfHeight = (USHORT)(shell.Height() / 2);
            ((Memory*)views["memory"])->Fetch(device, L"TaskMgr.exe", 0, 0, 32);
            views["memory"]->Render(
              thirdWidth,
              halfHeight,
              shell.Width() - thirdWidth,
              halfHeight,
              &shell
            );
            //((Scanner*)views["scanner"])->Fetch(device);
            //views["scanner"]->Render(
            //  0,
            //  0,
            //  thirdWidth,
            //  shell.Height(),
            //  &shell
            //);
            //((Debugger*)views["debugger"])->Fetch(device);
            //views["debugger"]->Render(
            //  thirdWidth,
            //  0,
            //  shell.Width() - thirdWidth,
            //  shell.Height() - halfHeight,
            //  &shell
            //);
            mode = Idle;
            break;
          }
        }
        shell.Poll();
        break;
      };
    }
  }
}
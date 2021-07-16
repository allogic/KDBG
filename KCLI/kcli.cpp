#include "global.h"
#include "shell.h"

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

enum State
{
  None,
  Exit,
};

std::int32_t wmain(std::int32_t argc, wchar_t* argv[])
{
  Shell shell;
  State state = None;
  while (state != Exit)
  {
    shell.Poll();
    switch (state)
    {
      case None:
      {
        shell.Clear(0, 0, shell.Width(), shell.Height());
        shell.Frame(0, 0, shell.Width(), 9);
        shell.Text(2, 0, L"Stack");
        shell.Frame(0, 10, shell.Width(), 9);
        shell.Text(2, 10, L"Memory");
        shell.Frame(0, 20, shell.Width(), 9);
        shell.Text(2, 20, L"Debugger");
        break;
      }
    }
  };
}
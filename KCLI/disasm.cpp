#include "disasm.h"

VOID
DisassembleBytes(
  PBYTE bytes,
  ULONG size,
  ULONG offset)
{
  csh csHandle;
  cs_err error = cs_open(CS_ARCH_X86, CS_MODE_64, &csHandle);
  if (error)
  {
    printf("cs_open\n");
    return;
  }
  cs_insn* instructions = NULL;
  ULONG numInstructions = (ULONG)cs_disasm(csHandle, bytes, size, offset, 0, &instructions);
  if (numInstructions)
  {
    for (ULONG i = 0; i < numInstructions; ++i)
    {
      printf("0x%08X ", (ULONG)instructions[i].address);
      for (ULONG j = 0; j < 23; ++j)
      {
        if (j < instructions[i].size)
          printf("%02X ", instructions[i].bytes[j]);
        else
          printf(".. ");
      }
      printf("%s %s\n", instructions[i].mnemonic, instructions[i].op_str);
    }
  }
  cs_free(instructions, numInstructions);
  cs_close(&csHandle);
}
#include "util.h"

ULONG GetProcessId(PWCHAR processName)
{
  PROCESSENTRY32 pe;
  pe.dwSize = sizeof(PROCESSENTRY32);
  PVOID snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (!Process32First(snapshot, &pe))
  {
    CloseHandle(snapshot);
    return 0;
  }
  do
  {
    if (_wcsicmp(processName, pe.szExeFile) == 0)
    {
      ULONG pid = pe.th32ProcessID;
      CloseHandle(snapshot);
      return pid;
    }
  } while (Process32Next(snapshot, &pe));
  CloseHandle(snapshot);
  return 0;
}

VOID FreeMemory(PVOID pointer)
{
  free(pointer);
}

SIZE_T ArgvLength(PWCHAR argv)
{
  SIZE_T length = 0;
  while (*(argv++))
    ++length;
  return ++length;
}
PBYTE ArgvToBytes(PWCHAR argv)
{
  SIZE_T numChars = ArgvLength(argv);
  SIZE_T numBytes = sizeof(WCHAR) * numChars;
  PBYTE result = (PBYTE)malloc(numBytes);
  WCHAR byte[2];
  for (SIZE_T i = 0, j = 0; i < (numChars - 2); i += 2, ++j)
  {
    memcpy(byte, argv + i, sizeof(WCHAR) * 2);
    result[j] = (BYTE)wcstoul(byte, NULL, 16);
  }
  return result;
}
PWCHAR ArgvToWcStr(PWCHAR argv)
{
  SIZE_T numBytes = sizeof(WCHAR) * ArgvLength(argv);
  PWCHAR result = (PWCHAR)malloc(numBytes);
  wcscpy_s(result, numBytes, argv);
  return result;
}
PCHAR ArgvToMbStr(PWCHAR argv)
{
  SIZE_T numBytes = sizeof(CHAR) * ArgvLength(argv);
  PCHAR result = (PCHAR)malloc(numBytes);
  wcstombs_s(NULL, result, numBytes, argv, 256);
  return result;
}

VOID DisassembleBytes(PBYTE bytes, SIZE_T size, SIZE_T offset)
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
  SIZE_T numInstructions = cs_disasm(csHandle, bytes, size, offset, 0, &instructions);
  if (numInstructions)
  {
    // Print assembly instructions
    for (SIZE_T i = 0; i < numInstructions; ++i)
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
  // Cleanup
  cs_free(instructions, numInstructions);
  cs_close(&csHandle);
}
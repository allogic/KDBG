#include "global.h"

// TODO: Strengthen response usage via std::vector/set/etc..
// TODO: Refactor into std c++ / remove all windows thingies

/*
* Program usage:
*   - Global
*      - /Attach pid
*      - /Info
*   - Scanning
*      - /New modules count operator mask type (value ...)
*      - /Next modules count operator mask type (value ...)
*      - /Undo
*   - Memory
*      - /Read base offset size
*      - /Write base offset size bytes
*      - /Dasm base offset size
*   - Debugger
*      - /Attach tid
*      - /SetBreak base type
*      - /RemBreak base type
*      - /Step
*      - /StepOver
*      - /StepInto
*      - /Suspend
*      - /Resume
*      - /Context
*      - /Stack
*/

/*
* I/O communication.
*/

#define KMOD_REQ_SCAN_INT_SIGNED CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0100, METHOD_IN_DIRECT, FILE_SPECIAL_ACCESS)
#define KMOD_REQ_SCAN_CONTEXT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0101, METHOD_IN_DIRECT, FILE_SPECIAL_ACCESS)
#define KMOD_REQ_SCAN_STACK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0102, METHOD_IN_DIRECT, FILE_SPECIAL_ACCESS)

typedef struct _REQ_SCAN_INT_SIGNED
{
  ULONG Pid;
  PWCHAR Name;
  ULONG Offset;
  SIZE_T Size;
  PVOID Buffer;
} REQ_SCAN_INT_SIGNED, * PREQ_SCAN_INT_SIGNED;
typedef struct _REQ_SCAN_CONTEXT
{
  ULONG Tid;
  ULONG Iterations; // Change to TIME_T
} REQ_SCAN_CONTEXT, * PREQ_SCAN_CONTEXT;
typedef struct _REQ_SCAN_STACK
{
  ULONG Tid;
  ULONG Iterations; // Change to TIME_T
} REQ_SCAN_STACK, * PREQ_SCAN_STACK;

/*
* Communication device.
*/

#define KMOD_DEVICE_NAME "\\\\.\\KMOD"

HANDLE Device = NULL;

/*
* Interpreter.
*/

struct ScanContext
{
  std::vector<char unsigned> CurrBytes{};
  std::vector<char unsigned> PrevBytes{};
};

std::vector<std::string> Tokenize(std::string& line)
{
  std::vector<std::string> tokens{};
  size_t offset{};
  while ((offset = line.find(' ')) != std::string::npos)
  {
    tokens.emplace_back(line.substr(0, offset));
    line = line.substr(0, offset);
  }
  tokens.emplace_back(line);
  return tokens;
}

/*
* Entry point.
*/

INT wmain(INT argc, PWCHAR argv[])
{
  // Connect to driver
  Device = CreateFileA(KMOD_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
  if (Device == INVALID_HANDLE_VALUE)
  {
    LOG_ERROR("Device connection cannot be established\n");
  }
  else
  {
    std::string line;
    ScanContext scanContext;
    while (std::getline(std::cin, line))
    {
      std::vector<std::string> tokens = Tokenize(line);
      // 
      if ("/Next")
      {

      }
      if ("/Read" == tokens[0])
      {
        REQ_SCAN_INT_SIGNED req;
        req.Pid = std::wcstoul(argv[2], NULL, 10);
        req.Name = (PWCHAR)std::malloc(sizeof(WCHAR) * std::wcslen(argv[3]));
        std::memcpy(req.Name, argv[3], sizeof(WCHAR) * std::wcslen(argv[3]));
        req.Offset = std::wcstoul(argv[4], NULL, 10);
        req.Size = sizeof(INT) * std::wcstoul(argv[5], NULL, 10);
        req.Buffer = (PINT)std::malloc(req.Size);
        // Issue request
        if (DeviceIoControl(Device, KMOD_REQ_SCAN_INT_SIGNED, &req, sizeof(req), &req, sizeof(req), NULL, NULL))
        {
          std::printf("");
          for (SIZE_T i = 0; i < (req.Size / sizeof(INT)); ++i)
          {
            std::printf("%u\n", ((PINT)req.Buffer)[i]);
          }
        }
        // Cleanup
        std::free(req.Name);
        std::free(req.Buffer);
      }
    }
    // Cleanup
    CloseHandle(Device);
  }
  return 0;
}
#ifndef KC_DISASSEMBLER_H
#define KC_DISASSEMBLER_H

#include <kc_core.h>

#include <capstone/capstone.h>

///////////////////////////////////////////////////////////
// Disassembler utilities
///////////////////////////////////////////////////////////

namespace kdbg
{
  class Disassembler
  {
  public:
    enum ProcessorMode
    {
      PROCESSOR_MODE_NONE,
      PROCESSOR_MODE_PROCESS,
      PROCESSOR_MODE_KERNEL,
    };

  public:
    Disassembler();
    virtual ~Disassembler();

  public:
    void Draw(float time);

    void SeekFromProcess(uint64_t base, uint32_t size);
    void SeekFromKernel(uint64_t base, uint32_t size);

  private:
    void DisassembleBytes();

    void Update();
    void PageUp();
    void PageDown();

    void ReplaceWithNop(uint64_t base, uint32_t size);

  private:
    csh _capstoneHandle = 0;

    cs_insn* _instructions = nullptr;
    uint32_t _instructionCount = 0;

    ProcessorMode _processorMode = PROCESSOR_MODE_NONE;

    uint64_t _base = 0;
    uint32_t _size = 0;

    std::vector<uint8_t> _bytes = {};

    char _baseOffsetBuffer[32] = {};
    uint64_t _baseOffset = 0;
  };
}

#endif
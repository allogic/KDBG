#ifndef KC_MEMORY_H
#define KC_MEMORY_H

#include <kc_core.h>

///////////////////////////////////////////////////////////
// Memory utilities
///////////////////////////////////////////////////////////

namespace kdbg
{
  class Memory
  {
  public:
    enum ProcessorMode
    {
      PROCESSOR_MODE_NONE,
      PROCESSOR_MODE_PROCESS,
      PROCESSOR_MODE_KERNEL,
    };

  public:
    Memory() = default;

  public:
    void Draw(float time);

    void SeekFromProcess(uint64_t base, uint32_t size);
    void SeekFromKernel(uint64_t base, uint32_t size);
  };
}

#endif
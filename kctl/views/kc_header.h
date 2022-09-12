#ifndef KC_HEADER_H
#define KC_HEADER_H

#include <kc_core.h>

///////////////////////////////////////////////////////////
// Header utilities
///////////////////////////////////////////////////////////

namespace kdbg
{

  class Header
  {
  public:
    Header() = default;

  public:
    void Draw(float time);

    void UpdateFromProcess(uint64_t base);
    void UpdateFromKernel(uint64_t base);

  private:
    IMAGE_DOS_HEADER _dosHeader = {};
    IMAGE_NT_HEADERS _ntHeaders = {};
    PIMAGE_DATA_DIRECTORY _dataDir = nullptr;
  };
}

#endif
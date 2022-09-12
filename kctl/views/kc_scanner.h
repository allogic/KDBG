#ifndef KC_SCANNER_H
#define KC_SCANNER_H

#include <kc_core.h>

///////////////////////////////////////////////////////////
// Scanner utilities
///////////////////////////////////////////////////////////

namespace kdbg
{
  class Scanner
  {
  public:
    Scanner() = default;

  public:
    void Draw(float time);

  private:
    std::vector<uint64_t> _scans = {};
  };
}

#endif
#ifndef KC_TOOLBAR_H
#define KC_TOOLBAR_H

#include <kc_core.h>

///////////////////////////////////////////////////////////
// Toolbar utilities
///////////////////////////////////////////////////////////

namespace kdbg
{
  class Toolbar
  {
  public:
    Toolbar() = default;

  public:
    void Draw(float time);

    inline bool IsProcessWindowOpen() const { return _openProcessWindow; }
    inline bool IsProcessImageWindowOpen() const { return _openProcessImageWindow; }
    inline bool IsKernelImageWindowOpen() const { return _openKernelImageWindow; }
    inline bool IsHeaderWindowOpen() const { return _openHeaderWindow; }
    inline bool IsDisassemblerWindowOpen() const { return _openDisassemblerWindow; }
    inline bool IsMemoryWindowOpen() const { return _openMemoryWindow; }
    inline bool IsScannerWindowOpen() const { return _openScannerWindow; }

  private:
    bool _openProcessWindow = true;
    bool _openProcessImageWindow = true;
    bool _openKernelImageWindow = true;
    bool _openHeaderWindow = true;
    bool _openDisassemblerWindow = true;
    bool _openMemoryWindow = true;
    bool _openScannerWindow = true;
  };
}

#endif
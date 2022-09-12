#ifndef KC_KERNEL_IMAGE_H
#define KC_KERNEL_IMAGE_H

#include <kc_core.h>
#include <kc_ioctrl.h>

#include <imgui/imgui.h>

///////////////////////////////////////////////////////////
// Kernel image utilities
///////////////////////////////////////////////////////////

namespace kdbg
{
  class KernelImage
  {
  public:
    enum Column
    {
      COLUMN_BASE,
      COLUMN_SIZE,
      COLUMN_NAME,
    };

  public:
    KernelImage() = default;

  public:
    void Draw(float time);

    inline uint64_t GetImageBase() const { return _selectedImage.Base; }

  private:
    void Update();

  public:
    bool operator() (const KERNEL_IMAGE& lhs, const KERNEL_IMAGE& rhs);

  private:
    std::vector<KERNEL_IMAGE> _images = {};
    KERNEL_IMAGE _selectedImage = {};
    ImGuiTableSortSpecs* _tableSortSpecs = nullptr;
  };
}

#endif
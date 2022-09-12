#ifndef KC_PROCESS_IMAGE_H
#define KC_PROCESS_IMAGE_H

#include <kc_core.h>
#include <kc_ioctrl.h>

#include <imgui/imgui.h>

///////////////////////////////////////////////////////////
// Process image utilities
///////////////////////////////////////////////////////////

namespace kdbg
{
  class ProcessImage
  {
  public:
    enum Column
    {
      COLUMN_BASE,
      COLUMN_SIZE,
      COLUMN_NAME,
    };

  public:
    ProcessImage() = default;

  public:
    void Draw(float time);

    inline uint64_t GetImageBase() const { return _selectedImage.Base; }

  private:
    void Update();

  public:
    bool operator() (const PROCESS_IMAGE& lhs, const PROCESS_IMAGE& rhs);

  private:
    std::vector<PROCESS_IMAGE> _images = {};
    PROCESS_IMAGE _selectedImage = {};
    ImGuiTableSortSpecs* _tableSortSpecs = nullptr;
  };
}

#endif
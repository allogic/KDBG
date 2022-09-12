#include <views/kc_memory.h>

#include <kc_ioctrl.h>

#include <imgui/imgui.h>

///////////////////////////////////////////////////////////
// Memory utilities
///////////////////////////////////////////////////////////

namespace kdbg
{
  void Memory::Draw(float time)
  {
    ImGui::Begin("Memory");

    ImGui::End();
  }

  void Memory::SeekFromProcess(uint64_t base, uint32_t size)
  {

  }

  void Memory::SeekFromKernel(uint64_t base, uint32_t size)
  {

  }
}
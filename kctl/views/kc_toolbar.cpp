#include <views/kc_toolbar.h>

#include <imgui/imgui.h>

///////////////////////////////////////////////////////////
// Toolbar utilities
///////////////////////////////////////////////////////////

namespace kdbg
{
  void Toolbar::Draw(float time)
  {
    if (ImGui::BeginMainMenuBar())
    {
      if (ImGui::BeginMenu("View"))
      {
        ImGui::MenuItem("Processes", "", _openProcessWindow);
        ImGui::Separator();
        ImGui::MenuItem("Process Images", "", _openProcessImageWindow);
        ImGui::MenuItem("Kernel Images", "", _openKernelImageWindow);
        ImGui::Separator();
        ImGui::MenuItem("Headers", "", _openHeaderWindow);
        ImGui::Separator();
        ImGui::MenuItem("Disassembler", "", _openDisassemblerWindow);
        ImGui::MenuItem("Memory", "", _openMemoryWindow);
        ImGui::Separator();
        ImGui::MenuItem("Scanner", "", _openScannerWindow);
        ImGui::EndMenu();
      }
      ImGui::EndMainMenuBar();
    }
  }
}
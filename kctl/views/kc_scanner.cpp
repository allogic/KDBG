#include <views/kc_scanner.h>
#include <views/kc_process.h>
#include <views/kc_process_image.h>

#include <kc_ioctrl.h>

#include <imgui/imgui.h>

///////////////////////////////////////////////////////////
// Externals
///////////////////////////////////////////////////////////

extern kdbg::Process g_process;
extern kdbg::ProcessImage g_processImage;

///////////////////////////////////////////////////////////
// Scanner utilities
///////////////////////////////////////////////////////////

namespace kdbg
{
  void Scanner::Draw(float time)
  {
    ImGui::Begin("Scanner");

    // Controls
    if (ImGui::Button("First Scan"))
    {
      ioctrl::ScanProcessFirst<int32_t>(g_process.GetPid(), g_processImage.GetImageBase(), 1234, SCAN_TYPE_BYTE32, _scans);
    }
    ImGui::SameLine();
    if (ImGui::Button("Next Scan"))
    {
      ioctrl::ScanProcessNext<void>(g_process.GetPid());
    }

    if (ImGui::BeginTable("ScanTable", 1, ImGuiTableFlags_Reorderable | ImGuiTableFlags_RowBg | ImGuiTableFlags_Sortable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV))
    {
      // Draw header
      ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoSort, 120.0f);
      ImGui::TableSetupScrollFreeze(0, 1);
      ImGui::TableHeadersRow();

      // Draw scans
      for (const auto& scan : _scans)
      {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        if (ImGui::Selectable(std::format("{:016X}", scan).c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
        {
          
        }
      }

      ImGui::EndTable();
    }

    ImGui::End();
  }
}
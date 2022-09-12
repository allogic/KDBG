#include <views/kc_kernel_image.h>
#include <views/kc_process.h>
#include <views/kc_header.h>
#include <views/kc_disassembler.h>
#include <views/kc_memory.h>

///////////////////////////////////////////////////////////
// Externals
///////////////////////////////////////////////////////////

extern kdbg::Process g_process;
extern kdbg::Header g_header;
extern kdbg::Disassembler g_disassembler;
extern kdbg::Memory g_memory;

///////////////////////////////////////////////////////////
// Kernel image utilities
///////////////////////////////////////////////////////////

namespace kdbg
{
  void KernelImage::Draw(float time)
  {
    ImGui::Begin("Kernel Images");

    // Controls
    if (ImGui::Button("Update"))
    {
      Update();
    }
    ImGui::SameLine();
    if (ImGui::Button("Seek Disassembler"))
    {
      g_disassembler.SeekFromKernel(_selectedImage.Base, 0x1000);
    }
    ImGui::SameLine();
    if (ImGui::Button("Seek Memory"))
    {
      g_memory.SeekFromKernel(_selectedImage.Base, 0x1000);
    }
    ImGui::SameLine();
    if (ImGui::Button("Headers"))
    {
      g_header.UpdateFromKernel(_selectedImage.Base);
    }
    ImGui::SameLine();
    ImGui::Text("%s", _selectedImage.Name);

    if (ImGui::BeginTable("KernelImageTable", 3, ImGuiTableFlags_Reorderable | ImGuiTableFlags_RowBg | ImGuiTableFlags_Sortable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV))
    {
      // Draw header
      ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoSort, 120.0f);
      ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 80.0f, COLUMN_SIZE);
      ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_DefaultSort, 0.0f, COLUMN_NAME);
      ImGui::TableSetupScrollFreeze(0, 1);
      ImGui::TableHeadersRow();

      // Sort images
      _tableSortSpecs = ImGui::TableGetSortSpecs();
      if (_tableSortSpecs)
      {
        if (_tableSortSpecs->SpecsDirty)
        {
          std::sort(_images.begin(), _images.end(), *this);
          _tableSortSpecs->SpecsDirty = false;
        }
      }

      // Draw images
      for (const auto& image : _images)
      {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        if (ImGui::Selectable(std::format("{:016X}", image.Base).c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
        {
          _selectedImage = image;
        }
        ImGui::TableNextColumn();
        ImGui::Text("%u", image.Size);
        ImGui::TableNextColumn();
        ImGui::Text("%s", image.Name);
      }
      ImGui::EndTable();
    }

    ImGui::End();
  }

  void KernelImage::Update()
  {
    ioctrl::ReadKernelImages(_images);
  }

  bool KernelImage::operator() (const KERNEL_IMAGE& lhs, const KERNEL_IMAGE& rhs)
  {
    for (int32_t n = 0; n < _tableSortSpecs->SpecsCount; n++)
    {
      const ImGuiTableColumnSortSpecs* specs = &_tableSortSpecs->Specs[n];
      int64_t delta = 0;
      switch (specs->ColumnUserID)
      {
        case COLUMN_NAME: delta = (int64_t)_stricmp(lhs.Name, rhs.Name); break;
        case COLUMN_SIZE: delta = (int64_t)lhs.Size - rhs.Size;        break;
      }
      if (delta > 0)
      {
        return (specs->SortDirection == ImGuiSortDirection_Ascending) ? 1 : 0;
      }
      if (delta < 0)
      {
        return (specs->SortDirection == ImGuiSortDirection_Ascending) ? 0 : 1;
      }
    }
    return 0;
  }
}

#include <views/kc_process.h>

#include <kc_ioctrl.h>

///////////////////////////////////////////////////////////
// Process utilities
///////////////////////////////////////////////////////////

namespace kdbg
{
  void Process::Draw(float time)
  {
    ImGui::Begin("Processes");

    // Controls
    if (ImGui::Button("Update"))
    {
      Update();
    }
    ImGui::SameLine();
    ImGui::Checkbox("Auto-Update", &_autoUpdate);
    ImGui::SameLine();
    ImGui::Text("%ls", _selectedProcess.Name);

    // Auto update
    if (_autoUpdate)
    {
      if ((time - _autoUpdateTimePrev) >= 1.0f)
      {
        Update();
        _autoUpdateTimePrev = time;
      }
    }

    if (ImGui::BeginTable("ProcessTable", 4, ImGuiTableFlags_Reorderable | ImGuiTableFlags_RowBg | ImGuiTableFlags_Sortable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV))
    {
      // Draw header
      ImGui::TableSetupColumn("Id", ImGuiTableColumnFlags_WidthFixed, 50.0f, COLUMN_ID);
      ImGui::TableSetupColumn("Parent", ImGuiTableColumnFlags_WidthFixed, 50.0f, COLUMN_PARENT);
      ImGui::TableSetupColumn("Threads", ImGuiTableColumnFlags_WidthFixed, 50.0f, COLUMN_THREADS);
      ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_DefaultSort, 0.0f, COLUMN_NAME);
      ImGui::TableSetupScrollFreeze(0, 1);
      ImGui::TableHeadersRow();

      // Sort processes
      _tableSortSpecs = ImGui::TableGetSortSpecs();
      if (_tableSortSpecs)
      {
        if (_tableSortSpecs->SpecsDirty)
        {
          if (_processes.size() > 1)
          {
            std::sort(_processes.begin(), _processes.end(), *this);
            //qsort(&Processes[0], Processes.size(), sizeof(Process), KcCompareProcessWithSortSpecs);
          }
          _tableSortSpecs->SpecsDirty = false;
        }
      }

      // Draw processes
      for (const auto& process : _processes)
      {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        if (ImGui::Selectable(std::format("{}", process.Id).c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
        {
          _selectedProcess = process;
        }
        ImGui::TableNextColumn();
        ImGui::Text("%u", process.Parent);
        ImGui::TableNextColumn();
        ImGui::Text("%u", process.Threads);
        ImGui::TableNextColumn();
        ImGui::Text("%ls", process.Name);
      }

      ImGui::EndTable();
    }

    ImGui::End();
  }

  void Process::Update()
  {
    // Clear processes
    _processes.clear();

    // Create snapshot
    HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    // Convert entries
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(snapshotHandle, &entry))
    {
      while (Process32Next(snapshotHandle, &entry))
      {
        PROCESS process;
        process.Id = entry.th32ProcessID;
        process.Parent = entry.th32ParentProcessID;
        process.Threads = entry.cntThreads;
        wcscpy_s(process.Name, entry.szExeFile);

        _processes.emplace_back(process);
      }
    }

    // Close snapshot
    if (snapshotHandle)
    {
      CloseHandle(snapshotHandle);
    }
  }

  bool Process::operator() (const PROCESS& lhs, const PROCESS& rhs)
  {
    for (int32_t n = 0; n < _tableSortSpecs->SpecsCount; n++)
    {
      const ImGuiTableColumnSortSpecs* specs = &_tableSortSpecs->Specs[n];
      int64_t delta = 0;
      switch (specs->ColumnUserID)
      {
        case COLUMN_ID:      delta = (int64_t)lhs.Id - rhs.Id;            break;
        case COLUMN_PARENT:  delta = (int64_t)lhs.Parent - rhs.Parent;    break;
        case COLUMN_THREADS: delta = (int64_t)lhs.Threads - rhs.Threads;  break;
        case COLUMN_NAME:    delta = (int64_t)_wcsicmp(lhs.Name, rhs.Name); break;
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
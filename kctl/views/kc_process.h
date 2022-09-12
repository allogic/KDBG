#ifndef KC_PROCESS_H
#define KC_PROCESS_H

#include <kc_core.h>

#include <imgui/imgui.h>

///////////////////////////////////////////////////////////
// Process data types
///////////////////////////////////////////////////////////

typedef struct _PROCESS
{
  uint32_t Id;
  uint32_t Parent;
  uint32_t Threads;
  wchar_t Name[260];
} PROCESS, * PPROCESS;

///////////////////////////////////////////////////////////
// Process utilities
///////////////////////////////////////////////////////////

namespace kdbg
{
  class Process
  {
  public:
    enum Column
    {
      COLUMN_ID,
      COLUMN_PARENT,
      COLUMN_THREADS,
      COLUMN_NAME,
    };

  public:
    Process() = default;

  public:
    void Draw(float time);

    inline uint32_t GetPid() const { return _selectedProcess.Id; }

  private:
    void Update();

  public:
    bool operator() (const PROCESS& lhs, const PROCESS& rhs);

  private:
    std::vector<PROCESS> _processes = {};
    PROCESS _selectedProcess = {};
    bool _autoUpdate = false;
    float _autoUpdateTimePrev = 0.0f;
    ImGuiTableSortSpecs* _tableSortSpecs = nullptr;
  };
}

#endif
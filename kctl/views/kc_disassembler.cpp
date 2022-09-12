#include <views/kc_disassembler.h>
#include <views/kc_process.h>

#include <kc_ioctrl.h>

#include <imgui/imgui.h>

///////////////////////////////////////////////////////////
// Externals
///////////////////////////////////////////////////////////

extern kdbg::Process g_process;

///////////////////////////////////////////////////////////
// Disassembler utilities
///////////////////////////////////////////////////////////

namespace kdbg
{
  Disassembler::Disassembler()
  {
    cs_open(CS_ARCH_X86, CS_MODE_64, &_capstoneHandle);
  }

  Disassembler::~Disassembler()
  {
    if (_capstoneHandle)
    {
      if (_instructions)
      {
        cs_free(_instructions, _instructionCount);
      }
      cs_close(&_capstoneHandle);
    }
  }

  void Disassembler::Draw(float time)
  {
    ImGui::Begin("Disassembler");

    // Controls
    if (ImGui::Button("Update"))
    {
      Update();
    }
    ImGui::SameLine();
    if (ImGui::Button("Page Up"))
    {
      PageUp();
    }
    ImGui::SameLine();
    if (ImGui::Button("Page Down"))
    {
      PageDown();
    }
    ImGui::SameLine();
    if (ImGui::InputText("BaseOffset", _baseOffsetBuffer, 32))
    {
      _baseOffset = strtoull(_baseOffsetBuffer, nullptr, 16);
      Update();
    }

    if (ImGui::BeginTable("DisassemblerTable", 4, ImGuiTableFlags_Reorderable | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV))
    {
      // Draw header
      ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 120.0f);
      ImGui::TableSetupColumn("Mnemonics", ImGuiTableColumnFlags_WidthFixed, 400.0f);
      ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 300.0f);
      ImGui::TableSetupColumn("Comments", ImGuiTableColumnFlags_WidthFixed, 100.0f);
      ImGui::TableSetupScrollFreeze(0, 1);
      ImGui::TableHeadersRow();

      // Draw disassembly
      for (uint32_t i = 0; i < _instructionCount; i++)
      {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        if (ImGui::Selectable(std::format("{:016X}", _base + _baseOffset + _instructions[i].address).c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
        {
          ReplaceWithNop(_base + _baseOffset + _instructions[i].address, _instructions[i].size);
        }
        ImGui::TableNextColumn();
        ImGui::Text("%s %s", _instructions[i].mnemonic, _instructions[i].op_str);
        ImGui::TableNextColumn();
        for (uint32_t j = 0; j < _instructions[i].size; j++)
        {
          ImGui::Text("%02X", _instructions[i].bytes[j]);
          if (j < (uint32_t)(_instructions[i].size - 1))
          {
            ImGui::SameLine();
          }
        }
        ImGui::TableNextColumn();
        ImGui::Text("#");
      }

      ImGui::EndTable();
    }

    ImGui::End();
  }

  void Disassembler::SeekFromProcess(uint64_t base, uint32_t size)
  {
    // Set processor mode
    _processorMode = PROCESSOR_MODE_PROCESS;

    // Set new base and size
    _base = base;
    _size = size;

    // Update bytes
    _bytes.resize(_size);
    ioctrl::ReadProcessMemory(g_process.GetPid(), _base + _baseOffset, &_bytes[0], _size);

    // Disassemble bytes
    DisassembleBytes();
  }

  void Disassembler::SeekFromKernel(uint64_t base, uint32_t size)
  {
    // Set processor mode
    _processorMode = PROCESSOR_MODE_KERNEL;

    // Set new base and size
    _base = base;
    _size = size;

    // Update bytes
    _bytes.resize(size);
    ioctrl::ReadKernelMemory(_base + _baseOffset, &_bytes[0], _size);

    // Disassemble bytes
    DisassembleBytes();
  }

  void Disassembler::DisassembleBytes()
  {
    if (_instructions)
    {
      cs_free(_instructions, _instructionCount);
      _instructions = nullptr;
      _instructionCount = 0;
    }
    _instructionCount = (uint32_t)cs_disasm(_capstoneHandle, &_bytes[0], _bytes.size(), 0, 0, &_instructions);
  }

  void Disassembler::ReplaceWithNop(uint64_t base, uint32_t size)
  {
    if (base >= 0 && size > 0)
    {
      // Create nop buffer
      std::vector<uint8_t> nops{};
      nops.resize(size);
      std::fill(nops.begin(), nops.end(), 0x90);

      // Write nops
      switch (_processorMode)
      {
        case PROCESSOR_MODE_PROCESS: ioctrl::WriteProcessMemory(g_process.GetPid(), base, &nops[0], size); break;
        case PROCESSOR_MODE_KERNEL: ioctrl::WriteKernelMemory(base, &nops[0], size); break;
      }
    }
  }

  void Disassembler::Update()
  {
    switch (_processorMode)
    {
      case PROCESSOR_MODE_PROCESS: SeekFromProcess(_base, 0x1000); break;
      case PROCESSOR_MODE_KERNEL: SeekFromKernel(_base, 0x1000); break;
    }
  }

  void Disassembler::PageUp()
  {
    switch (_processorMode)
    {
      case PROCESSOR_MODE_PROCESS: SeekFromProcess(_base - 0x1000, 0x1000); break;
      case PROCESSOR_MODE_KERNEL: SeekFromKernel(_base - 0x1000, 0x1000); break;
    }
  }

  void Disassembler::PageDown()
  {
    switch (_processorMode)
    {
      case PROCESSOR_MODE_PROCESS: SeekFromProcess(_base + 0x1000, 0x1000); break;
      case PROCESSOR_MODE_KERNEL: SeekFromKernel(_base + 0x1000, 0x1000); break;
    }
  }
}
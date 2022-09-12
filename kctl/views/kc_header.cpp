#include <views/kc_header.h>
#include <views/kc_process.h>

#include <kc_ioctrl.h>

#include <imgui/imgui.h>

///////////////////////////////////////////////////////////
// Externals
///////////////////////////////////////////////////////////

extern kdbg::Process g_process;

///////////////////////////////////////////////////////////
// Header utilities
///////////////////////////////////////////////////////////

namespace kdbg
{
  void Header::Draw(float time)
  {
    ImGui::Begin("Headers");

    ImGui::BeginGroup();
    ImGui::Text("e_magic:%X", _dosHeader.e_magic);
    ImGui::Text("e_cblp:%u", _dosHeader.e_cblp);
    ImGui::Text("e_cp:%u", _dosHeader.e_cp);
    ImGui::Text("e_crlc:%u", _dosHeader.e_crlc);
    ImGui::Text("e_cparhdr:%u", _dosHeader.e_cparhdr);
    ImGui::Text("e_minalloc:%u", _dosHeader.e_minalloc);
    ImGui::Text("e_maxalloc:%u", _dosHeader.e_maxalloc);
    ImGui::Text("e_ss:%u", _dosHeader.e_ss);
    ImGui::Text("e_sp:%u", _dosHeader.e_sp);
    ImGui::Text("e_csum:%u", _dosHeader.e_csum);
    ImGui::Text("e_ip:%u", _dosHeader.e_ip);
    ImGui::Text("e_cs:%u", _dosHeader.e_cs);
    ImGui::Text("e_lfarlc:%u", _dosHeader.e_lfarlc);
    ImGui::Text("e_ovno:%u", _dosHeader.e_ovno);
    ImGui::Text("e_oemid:%u", _dosHeader.e_oemid);
    ImGui::Text("e_oeminfo:%u", _dosHeader.e_oeminfo);
    ImGui::Text("e_lfanew:%016llX", _dosHeader.e_lfanew);
    ImGui::EndGroup();

    ImGui::Separator();

    ImGui::BeginGroup();
    ImGui::Text("Machine:%X", _ntHeaders.FileHeader.Machine);
    ImGui::Text("NumberOfSections:%u", _ntHeaders.FileHeader.NumberOfSections);
    ImGui::Text("TimeDateStamp:%u", _ntHeaders.FileHeader.TimeDateStamp);
    ImGui::Text("PointerToSymbolTable:%016llX", _ntHeaders.FileHeader.PointerToSymbolTable);
    ImGui::Text("NumberOfSymbols:%u", _ntHeaders.FileHeader.NumberOfSymbols);
    ImGui::Text("SizeOfOptionalHeader:%u", _ntHeaders.FileHeader.SizeOfOptionalHeader);
    ImGui::Text("Characteristics:%X", _ntHeaders.FileHeader.Characteristics);
    ImGui::EndGroup();

    ImGui::Separator();

    ImGui::BeginGroup();
    ImGui::Text("Magic:%X", _ntHeaders.OptionalHeader.Magic);
    ImGui::Text("MajorLinkerVersion:%X", _ntHeaders.OptionalHeader.MajorLinkerVersion);
    ImGui::Text("MinorLinkerVersion:%X", _ntHeaders.OptionalHeader.MinorLinkerVersion);
    ImGui::Text("SizeOfCode:%u", _ntHeaders.OptionalHeader.SizeOfCode);
    ImGui::Text("SizeOfInitializedData:%u", _ntHeaders.OptionalHeader.SizeOfInitializedData);
    ImGui::Text("SizeOfUninitializedData:%u", _ntHeaders.OptionalHeader.SizeOfUninitializedData);
    ImGui::Text("AddressOfEntryPoint:%016llX", _ntHeaders.OptionalHeader.AddressOfEntryPoint);
    ImGui::Text("BaseOfCode:%016llX", _ntHeaders.OptionalHeader.BaseOfCode);
    ImGui::Text("ImageBase:%016llX", _ntHeaders.OptionalHeader.ImageBase);
    ImGui::Text("SectionAlignment:%u", _ntHeaders.OptionalHeader.SectionAlignment);
    ImGui::Text("FileAlignment:%u", _ntHeaders.OptionalHeader.FileAlignment);
    ImGui::Text("MajorOperatingSystemVersion:%X", _ntHeaders.OptionalHeader.MajorOperatingSystemVersion);
    ImGui::Text("MinorOperatingSystemVersion:%X", _ntHeaders.OptionalHeader.MinorOperatingSystemVersion);
    ImGui::Text("MajorImageVersion:%X", _ntHeaders.OptionalHeader.MajorImageVersion);
    ImGui::Text("MinorImageVersion:%X", _ntHeaders.OptionalHeader.MinorImageVersion);
    ImGui::Text("MajorSubsystemVersion:%X", _ntHeaders.OptionalHeader.MajorSubsystemVersion);
    ImGui::Text("MinorSubsystemVersion:%X", _ntHeaders.OptionalHeader.MinorSubsystemVersion);
    ImGui::Text("Win32VersionValue:%X", _ntHeaders.OptionalHeader.Win32VersionValue);
    ImGui::Text("SizeOfImage:%u", _ntHeaders.OptionalHeader.SizeOfImage);
    ImGui::Text("SizeOfHeaders:%u", _ntHeaders.OptionalHeader.SizeOfHeaders);
    ImGui::Text("CheckSum:%X", _ntHeaders.OptionalHeader.CheckSum);
    ImGui::Text("Subsystem:%X", _ntHeaders.OptionalHeader.Subsystem);
    ImGui::Text("DllCharacteristics:%X", _ntHeaders.OptionalHeader.DllCharacteristics);
    ImGui::Text("SizeOfStackReserve:%u", _ntHeaders.OptionalHeader.SizeOfStackReserve);
    ImGui::Text("SizeOfStackCommit:%u", _ntHeaders.OptionalHeader.SizeOfStackCommit);
    ImGui::Text("SizeOfHeapReserve:%u", _ntHeaders.OptionalHeader.SizeOfHeapReserve);
    ImGui::Text("SizeOfHeapCommit:%u", _ntHeaders.OptionalHeader.SizeOfHeapCommit);
    ImGui::Text("LoaderFlags:%X", _ntHeaders.OptionalHeader.LoaderFlags);
    ImGui::Text("NumberOfRvaAndSizes:%u", _ntHeaders.OptionalHeader.NumberOfRvaAndSizes);
    ImGui::EndGroup();

    ImGui::End();
  }

  void Header::UpdateFromProcess(uint64_t base)
  {
    _dosHeader = ioctrl::ReadProcessMemory<IMAGE_DOS_HEADER>(g_process.GetPid(), base);
    _ntHeaders = ioctrl::ReadProcessMemory<IMAGE_NT_HEADERS>(g_process.GetPid(), base + _dosHeader.e_lfanew);

    // Read data directory
    if (_ntHeaders.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
      _dataDir = ((PIMAGE_NT_HEADERS64)&_ntHeaders)->OptionalHeader.DataDirectory;
    }
    else
    {
      _dataDir = ((PIMAGE_NT_HEADERS32)&_ntHeaders)->OptionalHeader.DataDirectory;
    }
    ULONG exportDirRva = _dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ULONG exportDirSize = _dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
  }

  void Header::UpdateFromKernel(uint64_t base)
  {
    _dosHeader = ioctrl::ReadKernelMemory<IMAGE_DOS_HEADER>(base);
    _ntHeaders = ioctrl::ReadKernelMemory<IMAGE_NT_HEADERS>(base + _dosHeader.e_lfanew);

    // Read data directory
    if (_ntHeaders.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
      _dataDir = ((PIMAGE_NT_HEADERS64)&_ntHeaders)->OptionalHeader.DataDirectory;
    }
    else
    {
      _dataDir = ((PIMAGE_NT_HEADERS32)&_ntHeaders)->OptionalHeader.DataDirectory;
    }
    ULONG exportDirRva = _dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ULONG exportDirSize = _dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
  }
}
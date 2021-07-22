#include "thread.h"

NTSTATUS PsGetContextThread(
  PETHREAD Thread,
  PCONTEXT ThreadContext,
  KPROCESSOR_MODE Mode)
{
  return GetSystemRoutine<PSGETCONTEXTTHREAD>(L"PsGetContextThread")(
    Thread,
    ThreadContext,
    Mode);
}
NTSTATUS PsSetContextThread(
  PETHREAD Thread,
  PCONTEXT ThreadContext,
  KPROCESSOR_MODE Mode)
{
  return GetSystemRoutine<PSSETCONTEXTTHREAD>(L"PsSetContextThread")(
    Thread,
    ThreadContext,
    Mode);
}

VOID DumpContext(PCONTEXT context)
{
  KMOD_LOG_INFO("Control flags\n");
  KMOD_LOG_INFO("ContextFlags: %u\n", context->ContextFlags);
  KMOD_LOG_INFO("MxCsr: %u\n", context->MxCsr);
  KMOD_LOG_INFO("\n");
  KMOD_LOG_INFO("Segment registers and processor flags\n");
  KMOD_LOG_INFO("SegCs: %u\n", context->SegCs);
  KMOD_LOG_INFO("SegDs: %u\n", context->SegDs);
  KMOD_LOG_INFO("SegEs: %u\n", context->SegEs);
  KMOD_LOG_INFO("SegFs: %u\n", context->SegFs);
  KMOD_LOG_INFO("SegGs: %u\n", context->SegGs);
  KMOD_LOG_INFO("SegSs: %u\n", context->SegSs);
  KMOD_LOG_INFO("EFlags: %u\n", context->EFlags);
  KMOD_LOG_INFO("\n");
  KMOD_LOG_INFO("Debug registers\n");
  KMOD_LOG_INFO("Dr0: %llu\n", context->Dr0);
  KMOD_LOG_INFO("Dr1: %llu\n", context->Dr1);
  KMOD_LOG_INFO("Dr2: %llu\n", context->Dr2);
  KMOD_LOG_INFO("Dr3: %llu\n", context->Dr3);
  KMOD_LOG_INFO("Dr6: %llu\n", context->Dr6);
  KMOD_LOG_INFO("Dr7: %llu\n", context->Dr7);
  KMOD_LOG_INFO("\n");
  KMOD_LOG_INFO("Integer registers\n");
  KMOD_LOG_INFO("Rax: %llu\n", context->Rax);
  KMOD_LOG_INFO("Rcx: %llu\n", context->Rcx);
  KMOD_LOG_INFO("Rdx: %llu\n", context->Rdx);
  KMOD_LOG_INFO("Rbx: %llu\n", context->Rbx);
  KMOD_LOG_INFO("Rsp: %llu\n", context->Rsp);
  KMOD_LOG_INFO("Rbp: %llu\n", context->Rbp);
  KMOD_LOG_INFO("Rsi: %llu\n", context->Rsi);
  KMOD_LOG_INFO("Rdi: %llu\n", context->Rdi);
  KMOD_LOG_INFO("R8: %llu\n", context->R8);
  KMOD_LOG_INFO("R9: %llu\n", context->R9);
  KMOD_LOG_INFO("R10: %llu\n", context->R10);
  KMOD_LOG_INFO("R11: %llu\n", context->R11);
  KMOD_LOG_INFO("R12: %llu\n", context->R12);
  KMOD_LOG_INFO("R13: %llu\n", context->R13);
  KMOD_LOG_INFO("R14: %llu\n", context->R14);
  KMOD_LOG_INFO("R15: %llu\n", context->R15);
  KMOD_LOG_INFO("\n");
  KMOD_LOG_INFO("Program counter\n");
  KMOD_LOG_INFO("Rip: %llu\n", context->Rip);
  KMOD_LOG_INFO("\n");
  KMOD_LOG_INFO("Special debug control registers\n");
  KMOD_LOG_INFO("DebugControl: %llu\n", context->DebugControl);
  KMOD_LOG_INFO("LastBranchToRip: %llu\n", context->LastBranchToRip);
  KMOD_LOG_INFO("LastBranchFromRip: %llu\n", context->LastBranchFromRip);
  KMOD_LOG_INFO("LastExceptionToRip: %llu\n", context->LastExceptionToRip);
  KMOD_LOG_INFO("LastExceptionFromRip: %llu\n", context->LastExceptionFromRip);
  KMOD_LOG_INFO("\n");
}
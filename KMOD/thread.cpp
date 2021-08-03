#include "thread.h"

VOID KmDumpContext(PCONTEXT context)
{
  KM_LOG_ERROR("Control flags\n");
  KM_LOG_ERROR("ContextFlags: %lu\n", context->ContextFlags);
  KM_LOG_ERROR("MxCsr: %lu\n", context->MxCsr);
  KM_LOG_ERROR("\n");
  KM_LOG_ERROR("Segment registers and processor flags\n");
  KM_LOG_ERROR("SegCs: %u\n", context->SegCs);
  KM_LOG_ERROR("SegDs: %u\n", context->SegDs);
  KM_LOG_ERROR("SegEs: %u\n", context->SegEs);
  KM_LOG_ERROR("SegFs: %u\n", context->SegFs);
  KM_LOG_ERROR("SegGs: %u\n", context->SegGs);
  KM_LOG_ERROR("SegSs: %u\n", context->SegSs);
  KM_LOG_ERROR("EFlags: %lu\n", context->EFlags);
  KM_LOG_ERROR("\n");
  KM_LOG_ERROR("Debug registers\n");
  KM_LOG_ERROR("Dr0: %llu\n", context->Dr0);
  KM_LOG_ERROR("Dr1: %llu\n", context->Dr1);
  KM_LOG_ERROR("Dr2: %llu\n", context->Dr2);
  KM_LOG_ERROR("Dr3: %llu\n", context->Dr3);
  KM_LOG_ERROR("Dr6: %llu\n", context->Dr6);
  KM_LOG_ERROR("Dr7: %llu\n", context->Dr7);
  KM_LOG_ERROR("\n");
  KM_LOG_ERROR("Integer registers\n");
  KM_LOG_ERROR("Rax: %llu\n", context->Rax);
  KM_LOG_ERROR("Rcx: %llu\n", context->Rcx);
  KM_LOG_ERROR("Rdx: %llu\n", context->Rdx);
  KM_LOG_ERROR("Rbx: %llu\n", context->Rbx);
  KM_LOG_ERROR("Rsp: %llu\n", context->Rsp);
  KM_LOG_ERROR("Rbp: %llu\n", context->Rbp);
  KM_LOG_ERROR("Rsi: %llu\n", context->Rsi);
  KM_LOG_ERROR("Rdi: %llu\n", context->Rdi);
  KM_LOG_ERROR("R8: %llu\n", context->R8);
  KM_LOG_ERROR("R9: %llu\n", context->R9);
  KM_LOG_ERROR("R10: %llu\n", context->R10);
  KM_LOG_ERROR("R11: %llu\n", context->R11);
  KM_LOG_ERROR("R12: %llu\n", context->R12);
  KM_LOG_ERROR("R13: %llu\n", context->R13);
  KM_LOG_ERROR("R14: %llu\n", context->R14);
  KM_LOG_ERROR("R15: %llu\n", context->R15);
  KM_LOG_ERROR("\n");
  KM_LOG_ERROR("Program counter\n");
  KM_LOG_ERROR("Rip: %llu\n", context->Rip);
  KM_LOG_ERROR("\n");
  KM_LOG_ERROR("Special debug control registers\n");
  KM_LOG_ERROR("DebugControl: %llu\n", context->DebugControl);
  KM_LOG_ERROR("LastBranchToRip: %llu\n", context->LastBranchToRip);
  KM_LOG_ERROR("LastBranchFromRip: %llu\n", context->LastBranchFromRip);
  KM_LOG_ERROR("LastExceptionToRip: %llu\n", context->LastExceptionToRip);
  KM_LOG_ERROR("LastExceptionFromRip: %llu\n", context->LastExceptionFromRip);
  KM_LOG_ERROR("\n");
}
#include "trace.h"

VOID TraceContext(HANDLE tid, SIZE_T iterations)
{
  NTSTATUS status = STATUS_SUCCESS;
  PETHREAD thread = NULL;
  PCONTEXT context = NULL;
  SIZE_T contextSize = sizeof(CONTEXT);
  status = PsLookupThreadByThreadId(tid, &thread);
  status = ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID*)&context, 0, &contextSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  RtlZeroMemory(context, contextSize);
  KM_LOG_INFO("Rax Rcx Rdx Rbx Rsp Rbp Rsi Rdi\n");
  for (SIZE_T i = 0; i < iterations; ++i)
  {
    context->ContextFlags = CONTEXT_ALL;
    status = PsGetContextThread(thread, context, UserMode);
    KM_LOG_INFO("%llu %llu %llu %llu %llu %llu %llu %llu\n", context->Rax, context->Rcx, context->Rdx, context->Rbx, context->Rsp, context->Rbp, context->Rsi, context->Rdi);
  }
  if (context)
  {
    ZwFreeVirtualMemory(ZwCurrentProcess(), (PVOID*)context, &contextSize, MEM_RELEASE);
  }
  ObDereferenceObject(thread);
}
VOID TraceStack(HANDLE pid, HANDLE tid, PWCHAR moduleName, SIZE_T iterations)
{
  //NTSTATUS status = STATUS_SUCCESS;
  //PEPROCESS process = NULL;
  //PETHREAD thread = NULL;
  //PCONTEXT context = NULL;
  //SIZE_T contextSize = sizeof(CONTEXT);
  //PLDR_DATA_TABLE_ENTRY modules = NULL;
  //PLDR_DATA_TABLE_ENTRY module = NULL;
  //PLIST_ENTRY moduleList = NULL;
  //PLIST_ENTRY moduleEntry = NULL;
  //STACK_FRAME_X64 stackFrame64;
  //PPEB64 peb = NULL;
  //KAPC_STATE apc;
  //// Get context infos
  //status = PsLookupProcessByProcessId(pid, &process);
  //KMOD_LOG_ERROR_IF_NOT_SUCCESS(status, "PsLookupProcessByProcessId %X", status);
  //status = PsLookupThreadByThreadId(tid, &thread);
  //KMOD_LOG_ERROR_IF_NOT_SUCCESS(status, "PsLookupThreadByThreadId %X\n", status);
  //status = ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID*)&context, 0, &contextSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  //KMOD_LOG_ERROR_IF_NOT_SUCCESS(status, "ZwAllocateVirtualMemory %X\n", status);
  //// Attach to process
  //KeStackAttachProcess(process, &apc);
  //// Get module base
  //peb = (PPEB64)PsGetProcessPeb(process);
  //KMOD_LOG_ERROR_IF_NOT(!peb, "PsGetProcessPeb\n");
  //modules = CONTAINING_RECORD(peb->Ldr->InLoadOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
  //moduleList = modules->InLoadOrderLinks.Flink;
  //moduleEntry = moduleList->Flink;
  //while (moduleEntry != moduleList)
  //{
  //  module = CONTAINING_RECORD(moduleEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
  //  if (wcscmp(moduleName, module->BaseDllName.Buffer) == 0)
  //  {
  //    break;
  //  }
  //  moduleEntry = moduleEntry->Flink;
  //}
  //KMOD_LOG_ERROR_IF_NOT(!module, "Module not found\n");
  //PVOID moduleBase = GetModuleBase((PBYTE)module->DllBase, *(PULONG)module->EntryPoint);
  //LOG_INFO("ModuleBase %p\n", moduleBase);
  ////ULONG moduleExportOffset = GetModuleExportOffset((PBYTE)module->DllBase, module->SizeOfImage, "");
  ////LOG_INFO("moduleExportOffset %p\n", moduleExportOffset);
  //// Dump exports
  //DumpModuleExports((PBYTE)module->DllBase, module->SizeOfImage);
  //// Dump stack frames
  //LOG_INFO("\n");
  //LOG_INFO("Stack Frames:\n");
  //for (SIZE_T i = 0; i < iterations; ++i)
  //{
  //  // Get context
  //  status = PsGetContextThread(thread, context, UserMode);
  //  KMOD_LOG_ERROR_IF_NOT_SUCCESS(status, "PsGetContextThread %X\n", status);
  //  // Get stack frame
  //  stackFrame64.AddrOffset = context->Rip; // Instruction ptr
  //  stackFrame64.StackOffset = context->Rsp; // Stack ptr
  //  stackFrame64.FrameOffset = context->Rbp; // Stack base ptr
  //  LOG_INFO("%4X %llu %llu %llu\n", i, stackFrame64.AddrOffset, stackFrame64.StackOffset, stackFrame64.FrameOffset);
  //}
  //// Detach from process
  //KeUnstackDetachProcess(&apc);
  //// Cleanup
  //if (context)
  //{
  //  ZwFreeVirtualMemory(ZwCurrentProcess(), (PVOID*)context, &contextSize, MEM_RELEASE);
  //}
  //ObDereferenceObject(thread);
  //ObDereferenceObject(process);
}
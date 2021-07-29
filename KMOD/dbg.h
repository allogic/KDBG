#ifndef _DBG_H
#define _DBG_H

#include "global.h"

#define X86_EFLAGS_TF           0x00000100 /* Trap flag */
#define X86_EFLAGS_IF           0x00000200 /* Interrupt Enable flag */
#define X86_EFLAGS_IOPL         0x00003000 /* I/O Privilege Level bits */
#define X86_EFLAGS_NT           0x00004000 /* Nested Task flag */
#define X86_EFLAGS_RF           0x00010000 /* Resume flag */
#define X86_EFLAGS_VM           0x00020000 /* Virtual Mode */
#define X86_EFLAGS_ID           0x00200000 /* CPUID detection flag */

#define X86_CR0_PE              0x00000001 /* enable Protected Mode */
#define X86_CR0_NE              0x00000020 /* enable native FPU error reporting */
#define X86_CR0_TS              0x00000008 /* enable exception on FPU instruction for task switch */
#define X86_CR0_EM              0x00000004 /* enable FPU emulation (disable FPU) */
#define X86_CR0_MP              0x00000002 /* enable FPU monitoring */
#define X86_CR0_WP              0x00010000 /* enable Write Protect (copy on write) */
#define X86_CR0_PG              0x80000000 /* enable Paging */

#define X86_CR4_PAE             0x00000020 /* enable physical address extensions */
#define X86_CR4_PGE             0x00000080 /* enable global pages */
#define X86_CR4_OSFXSR          0x00000200 /* enable FXSAVE/FXRSTOR instructions */
#define X86_CR4_OSXMMEXCPT      0x00000400 /* enable #XF exception */

/* EDX flags */
#define X86_FEATURE_FPU         0x00000001 /* x87 FPU is present */
#define X86_FEATURE_VME         0x00000002 /* Virtual 8086 Extensions are present */
#define X86_FEATURE_DBG         0x00000004 /* Debugging extensions are present */
#define X86_FEATURE_PSE         0x00000008 /* Page Size Extension is present */
#define X86_FEATURE_TSC         0x00000010 /* time stamp counters are present */
#define X86_FEATURE_PAE         0x00000040 /* physical address extension is present */
#define X86_FEATURE_CX8         0x00000100 /* CMPXCHG8B instruction present */
#define X86_FEATURE_SYSCALL     0x00000800 /* SYSCALL/SYSRET support present */
#define X86_FEATURE_MTTR        0x00001000 /* Memory type range registers are present */
#define X86_FEATURE_PGE         0x00002000 /* Page Global Enable */
#define X86_FEATURE_CMOV        0x00008000 /* "Conditional move" instruction supported */
#define X86_FEATURE_PAT         0x00010000 /* Page Attribute Table is supported */
#define X86_FEATURE_DS          0x00200000 /* Debug Store is present */
#define X86_FEATURE_MMX         0x00800000 /* MMX extension present */
#define X86_FEATURE_FXSR        0x01000000 /* FXSAVE/FXRSTOR instructions present */
#define X86_FEATURE_SSE         0x02000000 /* SSE extension present */
#define X86_FEATURE_SSE2        0x04000000 /* SSE2 extension present */
#define X86_FEATURE_HT          0x10000000 /* Hyper-Threading present */

/* ECX flags */
#define X86_FEATURE_SSE3        0x00000001 /* SSE3 is supported */
#define X86_FEATURE_MONITOR     0x00000008 /* SSE3 Monitor instructions supported */
#define X86_FEATURE_VMX         0x00000020 /* Virtual Machine eXtensions are available */
#define X86_FEATURE_SSSE3       0x00000200 /* Supplemental SSE3 are available */
#define X86_FEATURE_FMA3        0x00001000 /* Fused multiple-add supported */
#define X86_FEATURE_CX16        0x00002000 /* CMPXCHG16B instruction are available */
#define X86_FEATURE_PCID        0x00020000 /* Process Context IDentifiers are supported */
#define X86_FEATURE_SSE41       0x00080000 /* SSE 4.1 is supported */
#define X86_FEATURE_SSE42       0x00100000 /* SSE 4.2 is supported */
#define X86_FEATURE_POPCNT      0x00800000 /* POPCNT instruction is available */
#define X86_FEATURE_XSAVE       0x04000000 /* XSAVE family are available */

/* EDX extended flags */
#define X86_FEATURE_NX          0x00100000 /* NX support present */

#define X86_EXT_FEATURE_SSE3    0x00000001 /* SSE3 extension present */
#define X86_EXT_FEATURE_3DNOW   0x40000000 /* 3DNOW! extension present */

#define FRAME_EDITED        0xFFF8

#define X86_MSR_GSBASE          0xC0000101
#define X86_MSR_KERNEL_GSBASE   0xC0000102
#define X86_MSR_EFER            0xC0000080
#define X86_MSR_STAR            0xC0000081
#define X86_MSR_LSTAR           0xC0000082
#define X86_MSR_CSTAR           0xC0000083
#define X86_MSR_SFMASK          0xC0000084

#define EFER_SCE    0x0001
#define EFER_LME    0x0100
#define EFER_LMA    0x0400
#define EFER_NXE    0x0800
#define EFER_SVME   0x1000
#define EFER_FFXSR  0x4000

/*
* Macros for getting and setting special purpose registers in portable code.
*/

#define KeGetContextPc(Context)                          ((Context)->Rip)
#define KeSetContextPc(Context, ProgramCounter)          ((Context)->Rip = (ProgramCounter))
#define KeGetTrapFramePc(TrapFrame)                      ((TrapFrame)->Rip)
#define KiGetLinkedTrapFrame(x)                          (PKTRAP_FRAME)((x)->TrapFrame)
#define KeGetContextReturnRegister(Context)              ((Context)->Rax)
#define KeSetContextReturnRegister(Context, ReturnValue) ((Context)->Rax = (ReturnValue))
#define KdpSetSingleStep(Context)                        ((Context)->EFlags |= X86_EFLAGS_TF)

/*
* Debugging utilities.
*/

VOID KmSetSoftwareBreakpoint(PCONTEXT context)
{
  // continue from gdb_input.h
  KeSetContextPc(context, 0xCC); // int3
  KdpSetSingleStep(context);
  //PKTRAP_FRAME trapFrame = KeGetTrapFramePc(context);
  //KMOD_LOG_INFO("Trap flag %llu\n", );
}
VOID KmSetHardwareBreakpoint()
{

}

#endif
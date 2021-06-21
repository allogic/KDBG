#ifndef _ARM64_H
#define _ARM64_H

#include "global.h"

typedef struct _ARM64_NT_CONTEXT
{
  DWORD            ContextFlags;
  DWORD            Cpsr;
  union
  {
    struct
    {
      DWORD64 X0;
      DWORD64 X1;
      DWORD64 X2;
      DWORD64 X3;
      DWORD64 X4;
      DWORD64 X5;
      DWORD64 X6;
      DWORD64 X7;
      DWORD64 X8;
      DWORD64 X9;
      DWORD64 X10;
      DWORD64 X11;
      DWORD64 X12;
      DWORD64 X13;
      DWORD64 X14;
      DWORD64 X15;
      DWORD64 X16;
      DWORD64 X17;
      DWORD64 X18;
      DWORD64 X19;
      DWORD64 X20;
      DWORD64 X21;
      DWORD64 X22;
      DWORD64 X23;
      DWORD64 X24;
      DWORD64 X25;
      DWORD64 X26;
      DWORD64 X27;
      DWORD64 X28;
      DWORD64 Fp;
      DWORD64 Lr;
    } DUMMYSTRUCTNAME;
    DWORD64 X[31];
  } DUMMYUNIONNAME;
  DWORD64          Sp;
  DWORD64          Pc;
  ARM64_NT_NEON128 V[32];
  DWORD            Fpcr;
  DWORD            Fpsr;
  DWORD            Bcr[ARM64_MAX_BREAKPOINTS];
  DWORD64          Bvr[ARM64_MAX_BREAKPOINTS];
  DWORD            Wcr[ARM64_MAX_WATCHPOINTS];
  DWORD64          Wvr[ARM64_MAX_WATCHPOINTS];
} ARM64_NT_CONTEXT, * PARM64_NT_CONTEXT;

#endif
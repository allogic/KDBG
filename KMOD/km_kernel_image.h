#ifndef KM_KERNEL_IMAGE_H
#define KM_KERNEL_IMAGE_H

#include <km_core.h>
#include <km_ioctrl.h>

///////////////////////////////////////////////////////////
// Kernel image API
///////////////////////////////////////////////////////////

NTSTATUS
KmInitializeKernelImageList();

NTSTATUS
KmResetKernelImageList();

NTSTATUS
KmUpdateKernelImages(
  PDWORD32 count);

NTSTATUS
KmReadKernelImageList(
  DWORD32 count,
  PKERNEL_IMAGE images);

#endif
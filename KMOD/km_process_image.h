#ifndef KM_PROCESS_IMAGE_H
#define KM_PROCESS_IMAGE_H

#include <km_core.h>
#include <km_ioctrl.h>

///////////////////////////////////////////////////////////
// Process image API
///////////////////////////////////////////////////////////

NTSTATUS
KmInitializeProcessImageList();

NTSTATUS
KmResetProcessImageList();

NTSTATUS
KmUpdateProcessImages(
  DWORD32 pid,
  PDWORD32 count);

NTSTATUS
KmReadProcessImageList(
  DWORD32 count,
  PPROCESS_IMAGE images);

#endif
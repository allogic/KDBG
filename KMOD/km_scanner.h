#ifndef KM_SCANNER_H
#define KM_SCANNER_H

#include <km_core.h>
#include <km_ioctrl.h>

///////////////////////////////////////////////////////////
// Scanner API
///////////////////////////////////////////////////////////

NTSTATUS
KmInitializeScanList();

NTSTATUS
KmResetScanList();

NTSTATUS
KmScanProcessFirst(
  PSCAN_PROCESS_FIRST request,
  PDWORD32 count);

NTSTATUS
KmScanProcessNext(
  PSCAN_PROCESS_NEXT request);

NTSTATUS
KmReadScanList(
  DWORD32 count,
  PDWORD64 scans);

#endif
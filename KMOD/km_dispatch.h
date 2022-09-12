#ifndef KM_DISPATCH_H
#define KM_DISPATCH_H

#include <km_core.h>
#include <km_ioctrl.h>

///////////////////////////////////////////////////////////
// IRP handlers
///////////////////////////////////////////////////////////

NTSTATUS
KmOnIrpDflt(
  PDEVICE_OBJECT device,
  PIRP irp);

NTSTATUS
KmOnIrpCreate(
  PDEVICE_OBJECT device,
  PIRP irp);

NTSTATUS
KmOnIrpCtrl(
  PDEVICE_OBJECT device,
  PIRP irp);

NTSTATUS
KmOnIrpClose(
  PDEVICE_OBJECT device,
  PIRP irp);

#endif
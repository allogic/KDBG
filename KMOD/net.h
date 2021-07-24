#ifndef _NET_H
#define _NET_H

#include "global.h"

/*
* Global socket context.
*/

typedef struct _SOCKET_CONTEXT
{
  PWSK_SOCKET Socket = NULL;
} SOCKET_CONTEXT, * PSOCKET_CONTEXT;

/*
* Socket callbacks.
*/

NTSTATUS
OnSocketOpen(
  PDEVICE_OBJECT deviceObject,
  PIRP irp,
  PVOID context
);

NTSTATUS
OnSocketClose(
  PDEVICE_OBJECT deviceObject,
  PIRP irp,
  PVOID context
);

NTSTATUS
OnSocketAccept(
  PDEVICE_OBJECT deviceObject,
  PIRP irp,
  PVOID context
);

NTSTATUS
OnSendComplete(
  PDEVICE_OBJECT deviceObject,
  PIRP irp,
  PVOID context
);

NTSTATUS
OnReceiveComplete(
  PDEVICE_OBJECT deviceObject,
  PIRP irp,
  PVOID context
);

NTSTATUS
OnSocketIoCtrl(
  PWSK_SOCKET socket,
  WSK_CONTROL_SOCKET_TYPE requestType,
  ULONG controlCode,
  ULONG level,
  SIZE_T inputSize,
  PVOID inputBuffer,
  SIZE_T outputSize,
  PVOID outputBuffer,
  SIZE_T* outputSizeReturned,
  PIRP irp
);

NTSTATUS
RegisterSocket();

NTSTATUS
OpenSocket(
  PWSK_PROVIDER_NPI providerNpi,
  PVOID socketContext,
  PWSK_CLIENT_LISTEN_DISPATCH dispatch
);

NTSTATUS
CloseSocket(
  PWSK_SOCKET socket,
  PVOID context
);

NTSTATUS
AcceptConnection(
  PWSK_SOCKET socket,
  PVOID acceptSocketContext,
  PWSK_CLIENT_CONNECTION_DISPATCH acceptSocketDispatch
);

NTSTATUS
SendData(
  PWSK_SOCKET socket,
  PWSK_BUF buffer
);

NTSTATUS
ReceiveData(
  PWSK_SOCKET socket,
  PWSK_BUF buffer
);

#endif
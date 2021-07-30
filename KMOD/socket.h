#ifndef _SOCKET_H
#define _SOCKET_H

#include "global.h"

#ifdef __cplusplus
extern "C" {
#endif

  //////////////////////////////////////////////////////////////////////////
  // Structures.
  //////////////////////////////////////////////////////////////////////////

typedef struct _KSOCKET_ASYNC_CONTEXT
{
  KEVENT CompletionEvent;
  PIRP Irp;
} KSOCKET_ASYNC_CONTEXT, * PKSOCKET_ASYNC_CONTEXT;

typedef struct _KSOCKET
{
  PWSK_SOCKET	WskSocket;

  union
  {
    PVOID WskDispatch;

    PWSK_PROVIDER_CONNECTION_DISPATCH WskConnectionDispatch;
    PWSK_PROVIDER_LISTEN_DISPATCH WskListenDispatch;
    PWSK_PROVIDER_DATAGRAM_DISPATCH WskDatagramDispatch;
#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
    PWSK_PROVIDER_STREAM_DISPATCH WskStreamDispatch;
#endif
  };

  KSOCKET_ASYNC_CONTEXT AsyncContext;
} KSOCKET, * PKSOCKET;

NTSTATUS
NTAPI
KsInitialize(
  VOID
  );

VOID
NTAPI
KsDestroy(
  VOID
  );

NTSTATUS
NTAPI
KsGetAddrInfo(
  _In_ PUNICODE_STRING NodeName,
  _In_ PUNICODE_STRING ServiceName,
  _In_ PADDRINFOEXW Hints,
  _Out_ PADDRINFOEXW* Result
  );

VOID
NTAPI
KsFreeAddrInfo(
  _In_ PADDRINFOEXW AddrInfo
  );

NTSTATUS
NTAPI
KsCreateSocket(
  _Out_ PKSOCKET* Socket,
  _In_ ADDRESS_FAMILY AddressFamily,
  _In_ USHORT SocketType,
  _In_ ULONG Protocol,
  _In_ ULONG Flags
  );

NTSTATUS
NTAPI
KsCreateConnectionSocket(
  _Out_ PKSOCKET* Socket,
  _In_ ADDRESS_FAMILY AddressFamily,
  _In_ USHORT SocketType,
  _In_ ULONG Protocol
  );

NTSTATUS
NTAPI
KsCreateListenSocket(
  _Out_ PKSOCKET* Socket,
  _In_ ADDRESS_FAMILY AddressFamily,
  _In_ USHORT SocketType,
  _In_ ULONG Protocol
  );

NTSTATUS
NTAPI
KsCreateDatagramSocket(
  _Out_ PKSOCKET* Socket,
  _In_ ADDRESS_FAMILY AddressFamily,
  _In_ USHORT SocketType,
  _In_ ULONG Protocol
  );

NTSTATUS
NTAPI
KsDisconnect(
  _In_ PKSOCKET Socket
  );

NTSTATUS
NTAPI
KsCloseSocket(
  _In_ PKSOCKET Socket
  );

NTSTATUS
NTAPI
KsBind(
  _In_ PKSOCKET Socket,
  _In_ PSOCKADDR LocalAddress
  );

NTSTATUS
NTAPI
KsAccept(
  _In_ PKSOCKET Socket,
  _Out_ PKSOCKET* NewSocket,
  _Out_opt_ PSOCKADDR LocalAddress,
  _Out_opt_ PSOCKADDR RemoteAddress
  );

NTSTATUS
NTAPI
KsConnect(
  _In_ PKSOCKET Socket,
  _In_ PSOCKADDR RemoteAddress
  );

NTSTATUS
NTAPI
KsSendRecv(
  _In_ PKSOCKET Socket,
  _In_ PVOID Buffer,
  _Inout_ PULONG Length,
  _In_ ULONG Flags,
  _In_ BOOLEAN Send
  );

NTSTATUS
NTAPI
KsSendRecvUdp(
  _In_ PKSOCKET Socket,
  _In_ PVOID Buffer,
  _Inout_ PULONG Length,
  _In_ ULONG Flags,
  _In_ PSOCKADDR RemoteAddress,
  _In_ BOOLEAN Send
  );

NTSTATUS
NTAPI
KsSend(
  _In_ PKSOCKET Socket,
  _In_ PVOID Buffer,
  _Inout_ PULONG Length,
  _In_ ULONG Flags
  );

NTSTATUS
NTAPI
KsRecv(
  _In_ PKSOCKET Socket,
  _In_ PVOID Buffer,
  _Inout_ PULONG Length,
  _In_ ULONG Flags
  );

NTSTATUS
NTAPI
KsSendTo(
  _In_ PKSOCKET Socket,
  _In_ PVOID Buffer,
  _Inout_ PULONG Length,
  _In_ ULONG Flags,
  _In_ PSOCKADDR RemoteAddress
  );

NTSTATUS
NTAPI
KsRecvFrom(
  _In_ PKSOCKET Socket,
  _In_ PVOID Buffer,
  _Inout_ PULONG Length,
  _In_ ULONG Flags,
  _In_ PSOCKADDR RemoteAddress
  );

#ifdef __cplusplus
}
#endif

#endif
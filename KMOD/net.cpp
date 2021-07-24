#include "net.h"

NTSTATUS
OnSocketOpen(
  PDEVICE_OBJECT deviceObject,
  PIRP irp,
  PVOID context)
{
  UNREFERENCED_PARAMETER(deviceObject);
  KMOD_LOG_INFO("OnSocketCreate\n");
  if (irp->IoStatus.Status == STATUS_SUCCESS)
  {
    KMOD_LOG_INFO("Socket created\n");
  }
  IoFreeIrp(irp);
  return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
OnSocketClose(
  PDEVICE_OBJECT deviceObject,
  PIRP irp,
  PVOID context)
{
  UNREFERENCED_PARAMETER(deviceObject);
  KMOD_LOG_INFO("OnSocketDestroy\n");
  if (irp->IoStatus.Status == STATUS_SUCCESS)
  {
    KMOD_LOG_INFO("Socket destroyed\n");
  }
  IoFreeIrp(irp);
  return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
OnSocketAccept(
  PDEVICE_OBJECT deviceObject,
  PIRP irp,
  PVOID context)
{
  UNREFERENCED_PARAMETER(deviceObject);
  KMOD_LOG_INFO("OnAcceptComplete\n");
  if (irp->IoStatus.Status == STATUS_SUCCESS)
  {
    KMOD_LOG_INFO("New request\n");
  }
  IoFreeIrp(irp);
  return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
OnSendComplete(
  PDEVICE_OBJECT deviceObject,
  PIRP irp,
  PVOID context)
{
  UNREFERENCED_PARAMETER(deviceObject);
  PWSK_BUF datagramBuffer = NULL;
  ULONG byteCount = 0;
  KMOD_LOG_INFO("OnSendComplete\n");
  if (irp->IoStatus.Status == STATUS_SUCCESS)
  {
    datagramBuffer = (PWSK_BUF)context;
    byteCount = (ULONG)irp->IoStatus.Information;
    KMOD_LOG_INFO("Send %u bytes\n", byteCount);
  }
  IoFreeIrp(irp);
  return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
OnReceiveComplete(
  PDEVICE_OBJECT deviceObject,
  PIRP irp,
  PVOID context)
{
  UNREFERENCED_PARAMETER(deviceObject);
  PWSK_BUF datagramBuffer = NULL;
  ULONG byteCount = 0;
  KMOD_LOG_INFO("OnReceiveComplete\n");
  if (irp->IoStatus.Status == STATUS_SUCCESS)
  {
    datagramBuffer = (PWSK_BUF)context;
    byteCount = (ULONG)irp->IoStatus.Information;
    KMOD_LOG_INFO("Received %u bytes\n", byteCount);
  }
  IoFreeIrp(irp);
  return STATUS_MORE_PROCESSING_REQUIRED;
}

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
  PIRP irp)
{
  KMOD_LOG_INFO("OnSocketIoCtrl");
  return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
RegisterSocket()
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  WSK_REGISTRATION registration;
  WSK_CLIENT_DISPATCH appDispatch;
  WSK_CLIENT_NPI clientNpi;
  clientNpi.ClientContext = NULL;
  clientNpi.Dispatch = &appDispatch;
  status = WskRegister(&clientNpi, &registration);
  return status;
}

NTSTATUS
OpenSocket(
  PWSK_PROVIDER_NPI providerNpi,
  PVOID socketContext,
  PWSK_CLIENT_LISTEN_DISPATCH dispatch)
{
  PIRP irp = IoAllocateIrp(1, FALSE);
  IoSetCompletionRoutine(irp, OnSocketOpen, socketContext, TRUE, TRUE, TRUE);
  return providerNpi->Dispatch->WskSocket(providerNpi->Client, AF_INET, SOCK_STREAM, IPPROTO_TCP, WSK_FLAG_LISTEN_SOCKET, socketContext, dispatch, NULL, NULL, NULL, irp);
}

NTSTATUS
CloseSocket(
  PWSK_SOCKET socket,
  PVOID context)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  PWSK_PROVIDER_BASIC_DISPATCH dispatch = (PWSK_PROVIDER_BASIC_DISPATCH)socket->Dispatch;
  PIRP irp = IoAllocateIrp(1, FALSE);
  IoSetCompletionRoutine(irp, OnSocketClose, context, TRUE, TRUE, TRUE);
  return dispatch->WskCloseSocket(socket, irp);
}

NTSTATUS
AcceptConnection(
  PWSK_SOCKET socket,
  PVOID socketContext,
  PWSK_CLIENT_CONNECTION_DISPATCH acceptSocketDispatch)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  PWSK_PROVIDER_LISTEN_DISPATCH dispatch = (PWSK_PROVIDER_LISTEN_DISPATCH)socket->Dispatch;
  PIRP irp = IoAllocateIrp(1, FALSE);
  IoSetCompletionRoutine(irp, OnSocketAccept, socketContext, TRUE, TRUE, TRUE);
  status = dispatch->WskAccept(socket, 0, socketContext, acceptSocketDispatch, NULL, NULL, irp);
  return status;
}

NTSTATUS
SendData(
  PWSK_SOCKET socket,
  PWSK_BUF buffer)
{
  PWSK_PROVIDER_CONNECTION_DISPATCH dispatch = (PWSK_PROVIDER_CONNECTION_DISPATCH)socket->Dispatch;
  PIRP irp = IoAllocateIrp(1, FALSE);
  IoSetCompletionRoutine(irp, OnSendComplete, buffer, TRUE, TRUE, TRUE);
  return dispatch->WskSend(socket, buffer, 0, irp);
}

NTSTATUS
ReceiveData(
  PWSK_SOCKET socket,
  PWSK_BUF buffer)
{
  PWSK_PROVIDER_CONNECTION_DISPATCH dispatch = (PWSK_PROVIDER_CONNECTION_DISPATCH)socket->Dispatch;
  PIRP irp = IoAllocateIrp(1, FALSE);
  IoSetCompletionRoutine(irp, OnReceiveComplete, buffer, TRUE, TRUE, TRUE);
  return dispatch->WskReceive(socket, buffer, 0, irp);
}
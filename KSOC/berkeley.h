#pragma once
#include <ntddk.h>
#include <wsk.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int       socklen_t;
typedef intptr_t  ssize_t;

int unsigned htonl(int unsigned hostlong);
short unsigned htons(short unsigned hostshort);
int unsigned   ntohl(int unsigned netlong);
short unsigned ntohs(short unsigned netshort);

int getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res);
void freeaddrinfo(struct addrinfo *res);

int socket_connection(int domain, int type, int protocol);
int socket_listen(int domain, int type, int protocol);
int socket_datagram(int domain, int type, int protocol);
int connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen);
int listen(int sockfd, int backlog);
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int send(int sockfd, const void* buf, size_t len, int flags);
int sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
int recv(int sockfd, void* buf, size_t len, int flags);
int recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
int closesocket(int sockfd);

#define socket  socket_connection

#ifdef __cplusplus
}
#endif

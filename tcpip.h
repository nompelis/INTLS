#ifndef _TCPIP_H_
#define _TCPIP_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/un.h>
#include <dlfcn.h>
#include <errno.h>


//
// Function prototypes
//

int tcpip_socket_listen( int* inet_socket_,
                         struct sockaddr_in* socket_name,
                         int port, int backlog );

int tcpiip_socket_read( int socket, long int nusec_timeout,
                        size_t num, size_t* num_bytes, void* buffer );

int tcpip_socket_connect( int port, const char hostname[] );


#endif


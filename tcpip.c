#include "debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/un.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

#include "tcpip.h"


//
// a function to generically establish an IPv4 listening socket
//

int tcpip_socket_listen( int* inet_socket_,
                         struct sockaddr_in* socket_name,
                         int port, int backlog )
{
   int ierr=0;
#ifdef _DEBUG_TCPIP_
   FPRINTF( stdout, " [TCPDEBUG]  Bringing up daemon style socket \n" );
#endif

   int inet_socket = socket( AF_INET, SOCK_STREAM, 0 );
   if( inet_socket == -1 ) {
      FPRINTF( stdout, " [Error]  Could not open listening socket \n" );
      perror( "create inet socket");
      return 1;
   }
#ifdef _DEBUG_TCPIP_
   FPRINTF( stdout, " [TCPDEBUG]  Listening socket fd: %d \n", inet_socket );
#endif

   int optval=1;
#ifndef _OLDER_LINUX_
   setsockopt( inet_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
#else
   setsockopt( inet_socket, SOL_SOCKET, SO_REUSEADDR               ,
#endif
               &optval, sizeof(optval) );

   in_port_t inet_port = htons( port );
#ifdef _DEBUG_TCPIP_
   FPRINTF( stdout, " [TCPDEBUG]  Using port: %d \n", port );
#endif
   memset( socket_name, 0, sizeof(struct sockaddr_in) );
   socket_name->sin_family = AF_INET;
   socket_name->sin_port = inet_port;
   socket_name->sin_addr.s_addr = INADDR_ANY;
   ierr = bind( inet_socket,
                (const struct sockaddr *) socket_name, sizeof(struct sockaddr_in
) );
#ifdef _DEBUG_TCPIP_
   FPRINTF( stdout, " [TCPDEBUG]  Return from bind() is \"%d\"\n", ierr );
#endif
   if( ierr != 0 ) {
      FPRINTF( stdout, " [Error]  Could not bind() the socket\n" );
      perror("bind() INET socket");
      FPRINTF( stdout, "          The port may be taken.\n" );
      close( inet_socket );
      return 2;
   }

   ierr = listen( inet_socket, backlog );
#ifdef _DEBUG_TCPIP_
   FPRINTF( stdout, " [TCPDEBUG]  Return from listen() is \"%d\"\n", ierr );
#endif
   if( ierr != 0 ) {
      FPRINTF( stdout, " [Error]  Could not listen() with the socket\n" );
      perror("listen() INET socket");
      close( inet_socket );
      return 3;
   }

   *inet_socket_ = inet_socket;

   return 0;
}


//
// Function to read a chunk of a specific size from a IPv4 socket while
// imposing a timeout. Requires an appropriatelly sized buffer and writes
// the number of bytes read to the pointed variable. Returned values:
// 1 -> connection dropped, -1 -> unknown conniection error
// 2 -> timeout reached, but some reading may have happened
//

int tcpip_socket_read( int socket, long int nusec_timeout,
                       size_t num, size_t* num_bytes, void* buffer )
{
   if( nusec_timeout <= 0 ) nusec_timeout = 5000000000;

   // record the start time
   struct timespec ts;
   clock_gettime( CLOCK_MONOTONIC, &ts );

   // polling timeout
   long int msec = nusec_timeout / 1000000000;
   long int musec = nusec_timeout - msec*1000000000;

   fd_set rfds;
   struct timeval tv;
   int nfds;

   FD_ZERO( &rfds );
   nfds = socket + 1;

   int ierr=0;
   *num_bytes=0;
   while( num && ierr == 0 ) {
      // set the descriptor
      FD_CLR( socket, &rfds );
      FD_SET( socket, &rfds );

      // setting timeout values for select
      tv.tv_sec = (time_t) msec;
      tv.tv_usec = (suseconds_t) musec;

      int isel = select( nfds, &rfds, NULL, NULL, &tv );
#ifdef _DEBUG2_NETWORK_IO_
      FPRINTF( stdout, " [NETIODEBUG]  Return from select() is %d \n", isel );
#endif
      if( isel > 0 ) {   // num of fds should be 1, and it is always "socket"
         ssize_t nb = read( socket, buffer+(*num_bytes), num );
         if( nb > 0 ) {
#ifdef _DEBUG2_NETWORK_IO_
            FPRINTF( stdout, " [NETIODEBUG]  Read %ld bytes \n", nb );
#endif
            *num_bytes += nb;
            num -= nb;
         } else if( nb == 0 ) {
#ifdef _DEBUG2_NETWORK_IO_
            FPRINTF( stdout, " [NETIODEBUG]  Connection was dropped\n" );
#endif
            ierr=1;
         } else {   // returns on error
#ifdef _DEBUG2_NETWORK_IO_
            FPRINTF( stdout, " [NETIODEBUG]  Unknown connection error!\n" );
#endif
            ierr=-1;
         }
      }

      struct timespec ts2;
      clock_gettime( CLOCK_MONOTONIC, &ts2 );
      long int nusec = (ts2.tv_sec - ts.tv_sec) * 1000000000 +
                       (ts2.tv_nsec - ts.tv_nsec);
#ifdef _DEBUG2_NETWORK_IO_
      FPRINTF( stdout, " [NETIODEBUG]  Time elapsed: %ld ns\n", nusec );
#endif
      if( nusec > nusec_timeout ) ierr=2;
   }

   if( *num_bytes < num ) {
#ifdef _DEBUG2_NETWORK_IO_
      FPRINTF( stdout, " [NETIODEBUG]  Received fewer bytes!\n" );
#endif
   }

   return ierr;
}


//
// Function to make an IPv4 connection to a server
//

int tcpip_socket_connect( int port, const char hostname[] )
{
   struct addrinfo hints, *results, *p;
   memset( &hints, 0, sizeof(struct addrinfo) );
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_protocol = 0;
   hints.ai_flags = AI_PASSIVE;
   hints.ai_canonname = NULL;
   hints.ai_addr = NULL;
   hints.ai_next = NULL;

   // get address information for this host
   int istat = getaddrinfo( hostname, NULL, &hints, &results );
   if( istat != 0 ) {
      FPRINTF( stdout, " [Error]  Could not get address info: %s\n",
               gai_strerror( istat ) );
      return -1;
   } else {
#ifdef _DEBUG_TCPIP_
      FPRINTF( stdout, " [TCPDEBUG]  Prepared hostname address info \n" );
#endif
   }

   char ipstr[INET6_ADDRSTRLEN]; 
   struct sockaddr_in addr;
   uint32_t s_addr;

   // sweep through results and connect to the first possible address
   for( p=results; p != NULL; p=p->ai_next ) {
#ifdef _DEBUG_TCPIP_
      FPRINTF( stdout, " [TCPDEBUG]  Addr info instance %p ", p );
#endif
      // check for IPv4 address, socket type, and protocol
      if( p->ai_family == AF_INET && p->ai_socktype == SOCK_STREAM ) {
         bzero( &addr, sizeof(addr) );
         memcpy( &addr, p->ai_addr, sizeof(struct sockaddr_in) );
         addr.sin_family = AF_INET;
         addr.sin_port = htons( port );
         s_addr = addr.sin_addr.s_addr;
         inet_ntop( p->ai_family, p->ai_addr, ipstr, sizeof(ipstr) );
#ifdef _DEBUG_TCPIP_
         fprintf( stdout, " addr: %.8x length: %d", s_addr,(int) p->ai_addrlen);
         fprintf( stdout, " (on the wire IP: %d.%d.%d.%d) %s\n", 
                  ( s_addr & 0x000000FF),
                  ( s_addr & 0x0000FF00) >> 8,
                  ( s_addr & 0x00FF0000) >> 16,
                  ( s_addr & 0xFF000000) >> 24, ipstr );
#endif

         break; // If we get here, we located a suitable connection address
      } else {
#ifdef _DEBUG_TCPIP_
         fprintf( stdout, "  - Not a candidate\n" );
#endif
      }
   }

   freeaddrinfo( results );

   if( p == NULL ) {
      FPRINTF( stdout, " [Error]  Could not find a suitable IPv4 address \n" );
      return -2;
   }

   int inet_socket = socket( PF_INET, SOCK_STREAM, 0 );
   if( inet_socket == -1 ) {
      FPRINTF( stdout, " [Error]  Could not create socket \n" );
      perror("socket creation failed");
   } else {
#ifdef _DEBUG_TCPIP_
      FPRINTF( stdout, " [TCPDEBUG]  Created INET socket \n" );
#endif
   }

   int iret = connect( inet_socket, (struct sockaddr*) &addr, sizeof(addr) );
   if( iret == 0 ) {
      FPRINTF( stdout, " [INFO]  Connected to \"%s\" \n", hostname );
   } else {
      FPRINTF( stdout, " [Error]  Connection to \"%s\" failed \n", hostname );
      close( inet_socket );
      return -3;
   }

   return inet_socket;
}


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <math.h>
#include <sys/time.h>
#include <time.h>

#include "tcpip.h"
#include "inossl.h"

#include <fcntl.h>

#include <pthread.h>


#define MAX_HEADER_SIZE (8192)

struct inPthread_s {
   pthread_t tid;
   pthread_attr_t tattr;
   int inet_socket;
   struct sockaddr_in client_address;
   int (*function)(void*);
   // per-case payload
   struct inOSSL_data_s ossl_data;
   unsigned char buffer[MAX_HEADER_SIZE];
};


//
// Function to negotiate a TLS handshake and read and respond to a web client
//

int dummy_demo( void* ptr )
{
   struct inPthread_s *p = (struct inPthread_s *) ptr;
   struct inOSSL_data_s* ossl = &(p->ossl_data);
   int ierr=0;
#ifdef _DEBUG_
   memset( p->buffer, 'F', MAX_HEADER_SIZE ); // make sure we can see problems!
#endif

   ossl->ssl = SSL_new( ossl->sslctx );
   if( ossl->ssl == NULL ) {
      fprintf( stdout, " [THREAD]  Failed with \"SSL_new()\"\n" );
      ierr=1;
   } else {
      fprintf( stdout, " [THREAD]  Got handle from \"SSL_new()\"\n" );
      SSL_set_fd( ossl->ssl, ossl->socket );
      fprintf( stdout, " [THREAD]  Socket file descriptor: %d\n", ossl->socket);
   }

   if( ierr==0 ) {
      ierr = SSL_accept( ossl->ssl );
      if( ierr <= 0 ) {
         int err = SSL_get_error( ossl->ssl, ierr );
         fprintf( stdout, " [THREAD]  SSL_accept failed: %d\n", err );
         ERR_print_errors_fp( stdout );
         SSL_free( ossl->ssl );
         ierr=2;
      } else {
         ierr=0;
#ifdef _DEBUG_
         fprintf( stdout, " [THREAD]  TLS connection successfully accepted\n");
         fprintf( stdout, "  Client TLS version: %s\n",
                  SSL_get_version( ossl->ssl ));
         fprintf( stdout, "  Client cipher: %s\n", SSL_get_cipher( ossl->ssl ));
#endif
         ossl->client_cert = inOSSL_GetCertificate( ossl->ssl );
         inOSSL_ShowCertificate( ossl->client_cert );
         if( ossl->client_cert != NULL ) X509_free( ossl->client_cert );
      }
   }

   int bytes_tot=0;
#ifdef _USE_SSL_PEEK_
#ifdef _DEBUG_
   if( ierr==0 ) {
      fprintf( stdout, " [THREAD]  About to peek up to %d bytes\n",
               MAX_HEADER_SIZE );
   }
#endif
   while( ierr==0 && bytes_tot < MAX_HEADER_SIZE ) {
      int req_bytes = MAX_HEADER_SIZE - bytes_tot;
      int bytes = SSL_peek( ossl->ssl, p->buffer + bytes_tot, req_bytes );
      if( bytes <= 0 ) {
         int serr = SSL_get_error( ossl->ssl, bytes );
         if( serr == SSL_ERROR_WANT_READ || serr == SSL_ERROR_WANT_WRITE ) {
#ifdef _DEBUG_
            fprintf( stdout, " [THREAD]  SSL non-error --> continuing...\n" );
#endif
            continue;
         } else {
#ifdef _DEBUG_
            fprintf( stdout, " [THREAD]  Error reading from SSL socket\n" );
#endif
            ierr=3;
         }
      } else {
         p->buffer[bytes_tot + bytes] = '\0';
#ifdef _DEBUG_
         fprintf( stdout, " [THREAD]  Peek %d bytes from SSL socket\n", bytes );
         fprintf( stdout, "-->%s<--\n", (char*) p->buffer + bytes_tot );
#endif
         bytes_tot += bytes;
         char* cptr = (char*) (p->buffer + bytes_tot - 4);
         if( bytes_tot >= 4 ) 
         if( cptr[0] == '\r' )
         if( cptr[1] == '\n' )
         if( cptr[2] == '\r' )
         if( cptr[3] == '\n' ) {
#ifdef _DEBUG_
            fprintf( stdout, " [THREAD]  Peeked to end of request \n" );
#endif
            break;
         }
      }
   }
#endif

   bytes_tot=0;
#ifdef _DEBUG_
   if( ierr==0 ) {
      fprintf( stdout, " [THREAD]  About to read up to %d bytes\n",
               MAX_HEADER_SIZE );
   }
#endif
   while( ierr==0 && bytes_tot < MAX_HEADER_SIZE-1 ) {
      int req_bytes = MAX_HEADER_SIZE - 1 - bytes_tot;
      int bytes = SSL_read( ossl->ssl, p->buffer + bytes_tot, req_bytes );
      if( bytes <= 0 ) {
#ifdef _DEBUG_
         fprintf( stdout, " [THREAD]  Error reading from SSL socket\n" );
#endif
         ierr=3;
      } else {
         p->buffer[bytes_tot + bytes] = '\0';
#ifdef _DEBUG_
         fprintf( stdout, " [THREAD]  Read %d bytes from SSL socket\n", bytes );
         fprintf( stdout, "-->%s<--\n", (char*) p->buffer + bytes_tot );
#endif
         bytes_tot += bytes;
         char* cptr = (char*) (p->buffer + bytes_tot - 4);
         if( bytes_tot >= 4 ) 
         if( cptr[0] == '\r' )
         if( cptr[1] == '\n' )
         if( cptr[2] == '\r' )
         if( cptr[3] == '\n' ) {
#ifdef _DEBUG_
            fprintf( stdout, " [THREAD]  Reached end of request \n" );
#endif
            break;
         }
      }
   }
#ifdef _DEBUG_
   fprintf( stdout, " [THREAD]  Exited receiving loop: ierr=%d \n", ierr );
#endif

   // send a response...
   if( ierr==0 ) {
      fprintf( stdout, " [THREAD]  Got %d bytes msg:\n ====>\"%s\"<====\n",
               bytes_tot, (char*) p->buffer );

      sprintf( (char*) p->buffer,
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 14\r\n"
            "\r\n"
            "Hello, HTTPS!\n" );
      SSL_write( ossl->ssl, p->buffer, strlen((char*) p->buffer) );
   }

   inOSSL_ShutdownSSLSession( ossl->ssl );

   // drop the connection; accessing the fd from the thread's perspective
   shutdown( p->inet_socket, SHUT_RDWR );
   close( p->inet_socket );

   return 0;
}


//
// Function to negotiate a TLS handshake via a non-blocking socket, read a web
// client's request to a web server, open a TCP connection to it, and mediate
// all data exchanges. (UNDER CONSTRUCTION)
// Returns:     0 - Exiting and all went well
//              1 - Could not create SSL context
//            201 - Error with select() in TLS handshake (with SSL_accept())
//            202 - SSL error during TLS handshake (with SSL_accept())
//            301 - Header is too long (in receiving header)
//            302 - Error with selet() in receiving header
//            40x - Error with extracting a server name
//            50x - Error with connecting to the backend server
//            601 - Error with select() in sending header
//            602 - Timeout reached while sending header
//            603 - Error with send() while sending header (client dropped?)
//            701 - Error with select() while medaiting traffic
//            702 - Timeout reached while medaiting traffic
//

int dummy( void* ptr )
{
   struct inPthread_s *p = (struct inPthread_s *) ptr;
   struct inOSSL_data_s* ossl = &(p->ossl_data);
   int ierr=0;
#ifdef _DEBUG_
   memset( p->buffer, 'F', MAX_HEADER_SIZE ); // make sure we can see problems!
#endif

   ossl->ssl = SSL_new( ossl->sslctx );
   if( ossl->ssl == NULL ) {
      fprintf( stdout, " [THREAD]  Failed with \"SSL_new()\"\n" );
      ierr=1;
   } else {
      fprintf( stdout, " [THREAD]  Got handle from \"SSL_new()\"\n" );
      SSL_set_fd( ossl->ssl, ossl->socket );
      fprintf( stdout, " [THREAD]  Socket file descriptor: %d\n", ossl->socket);
   }

#ifdef _DEBUG_
   fprintf( stdout, " [THREAD]  Making connection socket non-blocking\n" );
#endif
   // make this socket non-blocking
   int flags = fcntl( ossl->socket, F_GETFL, 0 );
   fcntl( ossl->socket, F_SETFL, flags | O_NONBLOCK );

   // perform TLS handshake
#ifdef _DEBUG_
   fprintf( stdout, " [THREAD]  (Step 1) About to perform TLS handshake \n" );
#endif
   const char* servername=NULL;
   if( ierr==0 ) while(1) {
      ierr = SSL_accept( ossl->ssl );
      if( ierr == 1 ) {
#ifdef _DEBUG_
         fprintf( stdout, " [THREAD]  TLS connection successfully accepted\n");
         fprintf( stdout, "  Client TLS version: %s\n",
                  SSL_get_version( ossl->ssl ));
         fprintf( stdout, "  Client cipher: %s\n", SSL_get_cipher( ossl->ssl ));
#endif
         ossl->client_cert = inOSSL_GetCertificate( ossl->ssl );
         inOSSL_ShowCertificate( ossl->client_cert );
         if( ossl->client_cert != NULL ) X509_free( ossl->client_cert );
         servername = SSL_get_servername( ossl->ssl,
                                          TLSEXT_NAMETYPE_host_name );
#ifdef _DEBUG_
         fprintf( stdout, " [THREAD]  SSL server name: \"%s\"\n", servername );
#endif
         ierr=0;
         break;
      } else {
         int serr = SSL_get_error( ossl->ssl, ierr );
#ifdef _DEBUG_
         fprintf( stdout, " [THREAD]  SSL_accept() erroring: %d\n", serr );
#endif
         if( serr == SSL_ERROR_WANT_READ || serr == SSL_ERROR_WANT_WRITE ) {
            struct timeval tv = {5,0};  // 5 seconds timeout
            fd_set fds;
            FD_ZERO( &fds );
            FD_SET( ossl->socket, &fds );
            int iret = select( ossl->socket + 1,
                               serr == SSL_ERROR_WANT_READ  ? &fds : NULL,
                               serr == SSL_ERROR_WANT_WRITE ? &fds : NULL,
                               NULL, &tv );
            if( iret <= 0 ) {
               ierr=201;     // problem with select()
               break;
            }
            // continuing loop to let SSL handle internal actions
         } else {
            ERR_print_errors_fp( stdout );
            ierr=202;       // SSL error
            break;
         }
      }
   }

   // retrieve the header of the HTTP request from the client
   int bytes_tot=0;
#ifdef _DEBUG_
   if( ierr==0 ) {
      fprintf( stdout, " [THREAD]  (Step 2) About to read up to %d bytes hdr\n",
               MAX_HEADER_SIZE );
   }
#endif
   while( ierr==0 ) {
      int req_bytes = MAX_HEADER_SIZE - 1 - bytes_tot;
      // check of we are running out of buffer
      if( req_bytes == 0 ) {
         ierr=301;   // header is too long
         break;
      }
      int bytes = SSL_read( ossl->ssl, p->buffer + bytes_tot, req_bytes );
      if( bytes <= 0 ) {
         int serr = SSL_get_error( ossl->ssl, bytes );
#ifdef _DEBUG_
         fprintf( stdout, " [THREAD]  SSL_read() erroring: %d\n", serr );
#endif
         if( serr == SSL_ERROR_WANT_READ || serr == SSL_ERROR_WANT_WRITE ) {
            struct timeval tv = {5,0};  // 5 seconds timeout
            fd_set fds;
            FD_ZERO( &fds );
            FD_SET( ossl->socket, &fds );
            int iret = select( ossl->socket + 1,
                               serr == SSL_ERROR_WANT_READ  ? &fds : NULL,
                               serr == SSL_ERROR_WANT_WRITE ? &fds : NULL,
                               NULL, &tv );
            if( iret <= 0 ) {
               ierr=302;    // problem with select()
               break;
            }
            // continuing loop to let SSL handle internal actions
         } else {
            ERR_print_errors_fp( stdout );
            ierr=303;     // problem with SSL
            break;
         }
      } else {
         p->buffer[bytes_tot + bytes] = '\0';
#ifdef _DEBUG_
         fprintf( stdout, " [THREAD]  Read %d bytes from SSL socket\n", bytes );
         fprintf( stdout, "-->%s<--\n", (char*) p->buffer + bytes_tot );
#endif
         bytes_tot += bytes;
         char* cptr = (char*) (p->buffer + bytes_tot - 4);
         if( bytes_tot >= 4 ) 
         if( cptr[0] == '\r' )
         if( cptr[1] == '\n' )
         if( cptr[2] == '\r' )
         if( cptr[3] == '\n' ) {
#ifdef _DEBUG_
            fprintf( stdout, " [THREAD]  Reached end of request \n" );
#endif
            break;
         }
      }
   }
#ifdef _DEBUG_
   fprintf( stdout, " [THREAD]  Ended receiving loop: ierr=%d \n", ierr );
#endif
   int num_head = bytes_tot;   // size of first request (stored in the buffer)

   if( ierr==0 ) if( servername == NULL ) {
#ifdef _DEBUG_
      fprintf( stdout, " [THREAD]  (Step 2b) Need to extract server name\n" );
#endif
      // do what it takes to extract a hostname; set "ierr" on failure
      // A "400" code can be returned; what if we have no hostname?!?!
   }


   // open a connection to the backend server
/////// This needs to be changed in the code, but hardwired it for now kidz.
  servername = "localhost"; // HACK
   int backsock=-888;
   if( ierr==0 ) {
#ifdef _DEBUG_
      fprintf( stdout, " [THREAD]  (Step 3) Linking backend: ierr=%d \n", ierr);
#endif
      backsock = tcpip_socket_connect( 80, servername );
      if( backsock <= 0 ) {
         fprintf( stdout, " [Error]  Could not connect to backend \"%s\"\n",
                  servername );
         ierr=500;
      }
   }
#ifdef _DEBUG_
   fprintf( stdout, " [THREAD]  Linked to %d backend: ierr=%d\n",backsock,ierr);
   fflush( stdout );
#endif

   // send the initial request to the server
   bytes_tot=0;
#ifdef _DEBUG_
   if( ierr==0 ) {
      fprintf( stdout, " [THREAD]  (Step 4) About to send %d bytes to backnd\n",
               num_head );
   }
#endif
   while( ierr==0 && bytes_tot < num_head ) {
      fd_set wfds;
      FD_ZERO( &wfds );
      FD_SET( backsock, &wfds );

      struct timeval tv = {5,0};  // 5 seconds timeout

      int isel = select( backsock + 1, NULL, &wfds, NULL, &tv );
      if( isel < 0 ) {
         ierr=601;    // problem with select()
         break;
      } else if( isel == 0 ) {
         fprintf( stdout, " [THREAD]  Timeout reached while sending header\n" );
         ierr=602;    // timeout reached
      } else {

         int req_bytes = num_head - bytes_tot;
         int bytes = send( backsock, p->buffer + bytes_tot, req_bytes, 0 );
         if( bytes <= 0 ) {
#ifdef _DEBUG_
            fprintf( stdout, " [THREAD]  send() erroring: %d\n", bytes );
#endif
            ierr=603;    // error with send() while sending header
         } else {
#ifdef _DEBUG_
            fprintf( stdout, " [THREAD]  Sent %d bytes to backend\n", bytes );
#endif
            bytes_tot += bytes;
         }

      }
   }
#ifdef _DEBUG_
   fprintf( stdout, " [THREAD]  Ended header sending loop: ierr=%d \n", ierr );
   fflush( stdout );
#endif


   //
   // traffic mediation
   //
   int buf_size = MAX_HEADER_SIZE / 2;
   char *c2b_buf = (char*) p->buffer;
   char *b2c_buf = c2b_buf + buf_size;
   int c2b_len=0, c2b_sent=0;
   int b2c_len=0, b2c_sent=0;

   int nfds = ossl->socket;
   if( backsock > nfds ) nfds = backsock;
#ifdef _DEBUG_
   fprintf( stdout, " [THREAD]  OSSL socket: %d, backend socket: %d \n",
            ossl->socket, backsock );
   fprintf( stdout, " [THREAD]  Maximum socket file descriptor: %d\n", nfds );
   fflush( stdout );
#endif

#ifdef _DEBUG_
   if( ierr==0 )
      fprintf( stdout, " [THREAD]  (Step 5) Meadiating traffic \n" );
#endif
   // keep mediating traffic
   while( ierr==0 ) {
      fd_set rfds, wfds;
      FD_ZERO( &rfds ); FD_ZERO( &wfds );

      // Want to read from SSL client?
      if( c2b_len == 0 ) FD_SET( ossl->socket, &rfds );
      // Testing only when buffer is empty, for whether client wants to write.

      // Want to write to the backend?
      if( c2b_len > c2b_sent ) FD_SET( backsock, &wfds );
      // Testing only when buffer has data, for whether backend wants to read.

      // Want to read from the backend?
      if( b2c_len == 0 ) FD_SET( backsock, &rfds );
      // Testing only when buffer is empty, for whether backend wants to write.

      // Want to write to the SSL client?
      if( b2c_len > b2c_sent ) FD_SET( ossl->socket, &wfds );
      // Testing only when buffer has data, for whether client wants to read.

      struct timeval tv = {5,0};  // 5 second timeout
      int isel = select( nfds+1, &rfds, &wfds, NULL, &tv );
#ifdef _DEBUG_
      fprintf( stdout, " [THREAD]  Return from select: %d\n", isel );
#endif
      if( isel < 0 ) {
         fprintf( stdout, " [Error]  Unknown error %d from select()\n", isel );
         ierr=101;
         break;  // ERROR
      } else if( isel == 0 ) {
         // Timeout reached; this is fatal

      }

      if( FD_ISSET( ossl->socket, &rfds ) ) {
//printf(" Reading from SSL...\n" );
         int bytes_req = buf_size - c2b_len;
         int bytes = SSL_read( ossl->ssl, c2b_buf + c2b_len, bytes_req );
//printf(" ...bytes: %d \n", bytes );//HACK
         if( bytes <= 0 ) break;  // ERROR
         c2b_len = bytes;    // sending will work only with what we got here...
         c2b_sent = 0;       // ...because this is a new payload
      }

      if( c2b_len > c2b_sent )  // backend may want to read at all times...
                                // ...but we do not always have stuff to send
      if( FD_ISSET( backsock, &wfds ) ) {
//printf(" Sending to backend...\n" );
         int bytes = send( backsock, c2b_buf + c2b_sent, c2b_len - c2b_sent, 0);
//printf(" ...bytes: %d \n", bytes );//HACK
         if( bytes <= 0 ) break;  // ERROR
         c2b_sent += bytes;
         if( c2b_sent == c2b_len ) c2b_len = c2b_sent = 0;
      }

      if( FD_ISSET( backsock, &rfds ) ) {
//printf(" Receiving from backend...\n" );
         int bytes = recv( backsock, b2c_buf, buf_size, 0);
//printf(" ...bytes: %d \n", bytes );//HACK
         if( bytes <= 0 ) break;  // ERROR
         b2c_len = bytes;    // sending will work only with what we got here...
         b2c_sent = 0;       // ...because this is a new payload
      }

      if( b2c_len > b2c_sent )  // client may want to read at all times...
                                // ...but we do not always have stuff to send
      if( FD_ISSET( ossl->socket, &wfds ) ) {
//printf(" Writing to SSL...\n" );
         int bytes_sen = b2c_len - b2c_sent;
         int bytes = SSL_write( ossl->ssl, b2c_buf + b2c_sent, bytes_sen );
//printf(" ...bytes: %d \n", bytes );//HACK
         if( bytes <= 0 ) break;  // ERROR
         b2c_sent += bytes;
         if( b2c_sent == b2c_len ) b2c_len = b2c_sent = 0;
      }

   }


   // drop the connection to the backend
   if( backsock >= 0 ) {
      shutdown( backsock, SHUT_RDWR );
      close( backsock );
   }

   inOSSL_ShutdownSSLSession( ossl->ssl );

   // drop the connection; accessing the fd from the thread's perspective
   shutdown( p->inet_socket, SHUT_RDWR );
   close( p->inet_socket );

   return 0;
}


//
// The function that is spawned as a thread invokes the dictated function
// and clears memory on exit -- simple.
//

void *client_thread( void *arg )
{
   if( arg == NULL ) {
      fprintf( stdout, " [Error]  Argument to client thread is null!\n" );
      return NULL;
   }

   struct inPthread_s *p = (struct inPthread_s *) arg;

   if( p->function == NULL ) {
      fprintf( stdout, " [THREAD]  Function to execute is null! Returning.\n" );
   } else {
      p->function( arg );
   }

   pthread_attr_destroy( &( p->tattr ) );
   free( p );

#ifdef _DEBUG_
   fprintf( stdout, " [DEBUG:THREAD]  Returning \n" );
#endif
   return NULL;
}


//
// Function to spawn a thread to handle a client
// (It spawns the function "client_thread", which is responsible for cleaning
// up on error and on return from the "func()" that it will execute.)
//

int client_spawn( const struct inOSSL_data_s* server_data,
                  int client_fd, struct sockaddr_in client_address,
                  int (*func)(void *) )
{
   struct inPthread_s *p;
   p = (struct inPthread_s*) malloc( sizeof(struct inPthread_s) );
   if( p == NULL ) {
      fprintf( stdout, " [Error]  Could not allocate thread data \n");
      return -1;
   }

   memcpy( &(p->client_address), &client_address, sizeof(struct sockaddr_in) );
   p->function = func;
   p->inet_socket = client_fd;

   p->ossl_data.sslctx = server_data->sslctx;
   p->ossl_data.method = server_data->method;
   p->ossl_data.ca_cert = server_data->ca_cert;
   p->ossl_data.ca_path = server_data->ca_path;
   p->ossl_data.client_cert = NULL;
   memcpy( &(p->ossl_data.addr), &client_address, sizeof(struct sockaddr_in) );
   p->ossl_data.host = NULL;
   p->ossl_data.port = 0;
   p->ossl_data.socket = client_fd;
   p->ossl_data.ssl = NULL;

#ifdef _DEBUG_
   fprintf( stdout, " [SERVER]  Connection at: %s:%d fd: %d\n",
           inet_ntoa(client_address.sin_addr),
           ntohs(client_address.sin_port), client_fd );
   fprintf( stdout, " [SERVER]  Socket file descriptor: %d \n", client_fd );
#endif


   int iret = pthread_attr_init( &( p->tattr ) );
   if( iret != 0 ) {
      perror("creating pthread attributes");
      free( p );
      return 1;
   }

   iret = pthread_create( &( p->tid ), &( p->tattr ),
                          &client_thread, (void *) p );
   if( iret != 0 ) {
      perror("spawning pthread to serve client");
      pthread_attr_destroy( &( p->tattr ) );
      free( p );
      return 2;
   }

   pthread_detach( p->tid );
#ifdef _DEBUG_
   fprintf( stdout, " [DEBUG]  Spawned thread to handle client \n" );
#endif

   return 0;
}


//
// Function that is the main server loop reacting to connections
//

int server_mainloop( const struct inOSSL_data_s* server_data,
                     struct sockaddr_in *socket_name,
                     int (*func)(void *) )
{
   fd_set rfds;
   struct timeval tv;
   int inet_socket, nfds, isel;
   int client_fd;
   struct sockaddr_in client_address;
   socklen_t client_address_size = sizeof(struct sockaddr_in);

   if( server_data == NULL || socket_name == NULL ) return 1;

   inet_socket = server_data->socket;

#ifdef _DEBUG_
   fprintf( stdout, " [DEBUG]  Starting daemon main loop\n");
#endif
   while( 1 ) {
      // adding socket descriptor to the set to monitor with select
      FD_ZERO( &rfds );
      FD_SET( inet_socket, &rfds );
      nfds = inet_socket + 1;

      // setting timeout values for select
      tv.tv_sec = 1;
      tv.tv_usec = 0;

      isel = select( nfds, &rfds, NULL, NULL, &tv );
#ifdef _DEBUG_MAIN_
      fprintf( stdout, " [DEBUG]  Return from select() in MainLoop: %d\n",isel);
#endif
      if( isel > 0 ) {
         int k;
         for(k=0;k<nfds;++k) { // loop over descriptors

            if( k == inet_socket )
            if( FD_ISSET( inet_socket, &rfds ) ) {
#ifdef _DEBUG_
               fprintf( stdout, " [DEBUG]  Trapped inet socket activity\n" );
#endif
               client_fd = accept( inet_socket,
                                   (struct sockaddr *) &client_address,
                                   &client_address_size);
               if( client_fd == -1 ) {
                  fprintf( stdout, " [Error]  Client connecting\n" );
               } else {
                  if( client_spawn( server_data,
                                    client_fd, client_address, func ) ) {
                     fprintf( stdout, " [Error]  Unable to spawn. Dropping client. \n");
                     shutdown( client_fd, SHUT_RDWR );
                     close( client_fd );
                  } else {
                     // spawning was successful; maybe we log this in a log...
                  }
               }

            }   // daemon socket conditional

         }   // trapped descriptors sweep
      }   // select conditional

#ifdef _DEBUG_MAIN_
      fprintf( stdout, " [DEBUG]  Main thread (\"MainLoop\") looped...\n");
#endif
   }   // daemon infinite loop
#ifdef _DEBUG_
   fprintf( stdout, " [DEBUG]  Ending server main loop\n");
#endif

   return 0;
}



//
// Function that acts like a TLS/SSL server and turns into a "tunnel"
//

int start_server( int iport )
{
   struct inOSSL_data_s server_data;
   int ierr=0;

#ifdef _DEBUG_
   printf(" [SERVER]  IN's TLS server (built: %s %s)\n",__DATE__,__TIME__);
#endif

   // should get paths from either env variables or passed in
   server_data.ca_cert = NULL;
   server_data.ca_path = NULL;

   ierr = inOSSL_CreateServerFromFiles( &server_data,
                                        "demo_key.pem", "demo_cert.pem" );
   if( ierr ) {
      fprintf( stdout, " [SERVER] Could not create SSL server structures\n" );
      return 1;
   }

   struct sockaddr_in socket_name;
   ierr = tcpip_socket_listen( &(server_data.socket), &socket_name, iport,1000);
   if( ierr ) {
      fprintf( stdout, " [SERVER}  Failed to create listening server socket\n");
      (void) inOSSL_TerminateServer( &server_data );
      return 2;
   } else {
      fprintf( stdout, " [SERVER}  Created listening server socket \n");
   }

   // enter an event-loop to serve clients
// (void) server_mainloop( &server_data, &socket_name, &dummy_demo );
   (void) server_mainloop( &server_data, &socket_name, &dummy );

#ifdef _DEBUG_
   fprintf( stdout, " [SERVER]  Terminating server SSL context \n");
#endif
   (void) inOSSL_TerminateServer( &server_data );

   return 0;
}


//
// Driver (becomes a server or a client)
//

int main( int argc, char *argv[] )
{
   int ierr;

   ierr = inOSSL_InitializeSSL();
   if( ierr ) {
      fprintf( stdout, " [Error]  Could not initialize the SSL library\n" );
      return 1;
   }

   start_server( 443 );

   inOSSL_DestroySSL();

   return EXIT_SUCCESS;
}


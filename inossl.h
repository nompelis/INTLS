
#ifndef _INOSSL_H_
#define _INOSSL_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <math.h>
#include <sys/time.h>
#include <time.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>


//
// The structure that holds all the information for a server/client using SSL
//

struct inOSSL_data_s {
   SSL_CTX *sslctx;
   const SSL_METHOD* method;
   char *ca_cert, *ca_path;
   X509 *client_cert;
   struct sockaddr_in addr;
   struct hostent *host;
   int port;
   int socket;
   SSL *ssl;
};


//
// function prototypes
//

int inOSSL_InitializeSSL();

void inOSSL_DestroySSL();


int inOSSL_CreateServerFromFiles( struct inOSSL_data_s *p,
                                  const char keyfile[],
                                  const char certfile[] );

int inOSSL_LoadCertificates( SSL_CTX *ctx,
                             const char certfile[], const char keyfile[] );

int inOSSL_TerminateServer( struct inOSSL_data_s *p );

int inOSSL_ShutdownSSLSession( SSL *p );

X509* inOSSL_GetCertificate( SSL *ssl );

void inOSSL_ShowCertificate( X509 *cert );

void inOSSL_QueryVerifyResult( long result );



#endif


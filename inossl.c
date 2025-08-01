/******************************************************************************
 Code to do SSL server/client stuff using OpenSSL

 Copyright 2018-2025 by Ioannis Nompelis

 Ioannis Nompelis <nompelis@nobelware.com> 2019/03/27 - 2025/07/02
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <math.h>
#include <sys/time.h>
#include <time.h>

#include "inossl.h"


//
// Function to initialize the OpenSSL library
// (A lot of predefined constants seem to be created here...)
//

int inOSSL_InitializeSSL()
{
   int ierr;
   char FUNC[] = "inOSSL_InitializeSSL";

   ierr = SSL_library_init();
   if( ierr < 0 ) {
#ifdef _DEBUG_OSSL_
      fprintf( stdout, " [%s]  Could not initialize the SSL library \n", FUNC );
#endif
      return 1;
   }

#ifdef _DEBUG_OSSL_
   fprintf( stdout, " [%s]  Loading all algorithms \n", FUNC );
#endif
   OpenSSL_add_all_algorithms();

#ifdef _DEBUG_OSSL_
   fprintf( stdout, " [%s]  Loading various SSL library strings \n", FUNC );
#endif
   SSL_load_error_strings();
   ERR_load_BIO_strings();
   ERR_load_crypto_strings();

#ifdef _DEBUG_OSSL_
   fprintf( stdout, " [%s]  Initializing the SSL library \n", FUNC );
#endif

   return 0;
}


//
// Function to terminate the OpenSSL library
// (I have no idea what is being cleaned up here...)
//

void inOSSL_DestroySSL()
{
   char FUNC[] = "inOSSL_DestroySSL";
#ifdef _DEBUG_OSSL_
   fprintf( stdout, " [%s]  Destroying internal openSSL structures\n", FUNC);
#endif
   ERR_free_strings();
   EVP_cleanup();
}


//
// Function to shutdown an SSL session.
// This routine should be called every time a particular session is to terminate
// such that the SSL session pointer is cleaned up. It performs a two-step
// shutdown procedure as per the manual page. (I have not encountered any
// issues with sessions needing two steps to close, but the man page says that
// the two-step procedure with checking the return code is preferred.)
//

int inOSSL_ShutdownSSLSession( SSL *p )
{
#ifdef _DEBUG_OSSL_
   char FUNC[] = "inOSSL_ShutdownSSLSession";
#endif

   if( p == NULL ) {
#ifdef _DEBUG_OSSL_
      fprintf( stdout, " [%s]  The SSL session pointer is null!\n", FUNC );
#endif
      return -1;
   } else {
#ifdef _DEBUG_OSSL_
      fprintf( stdout, " [%s]  Shutting down the SSL session \n", FUNC );
#endif
   }

   int ierr=0;
   struct timespec start, now;
   clock_gettime( CLOCK_MONOTONIC, &start );

   while(1) {
      int shutdown_state = SSL_get_shutdown( p );
      if( shutdown_state & SSL_RECEIVED_SHUTDOWN ) {
         ierr = SSL_shutdown( p );
         if( ierr == 1 ) {
            ierr=0;
            break;  // clean shutdown
         } else if( ierr < 0 ) {
            int serr = SSL_get_error( p, ierr );
            if( serr != SSL_ERROR_WANT_READ && serr != SSL_ERROR_WANT_WRITE )
               ierr=3; // fatal error
            break;  // something went to hell
         }
      } else {
         ierr=2;
         break;   // peer has already dropped out
      }

      // Check hardwired timeout
      clock_gettime( CLOCK_MONOTONIC, &now );
      double elapsed = (now.tv_sec - start.tv_sec)
                     + (now.tv_nsec - start.tv_nsec) / 1e9;
      if( elapsed > 2000.0 / 1000.0) break;
   }


#ifdef _DEBUG_OSSL_
   fprintf( stdout, " [%s]  Freeing structure at %p\n", FUNC, p );
#endif
   SSL_free( p );

   return ierr;
}


//
// Function to load the private key and the corresponding certificate into
// the SSL context structure.
//
// This function seems to be needed by the "server" that will be serving to
// clients, and they need to verify its certificate. (Lots of ambiguity here.)
// Results are never internally fatal unless the certificate/key files are not
// found. The context can continue to work with no certificates, apparently,
// but I do not know what happens then.
//

int inOSSL_LoadCertificates( SSL_CTX *ctx,
                             const char certfile[], const char keyfile[] )
{
#ifdef _DEBUG_OSSL_
   char FUNC[] = "inOSSL_LoadCertificates";
   fprintf( stdout, " [%s]  Loading certificates \n", FUNC );
#endif
#ifdef _DEBUG_OSSL_
   fprintf( stdout, " [%s]  Loading certificate: \"%s\" \n", FUNC, keyfile );
#endif
   int ierr = SSL_CTX_use_certificate_file( ctx, certfile, SSL_FILETYPE_PEM );
   if( ierr <= 0 ) {
      fprintf( stdout, " [Error]  Could not load certificate file: \'%s\"\n",
               certfile );
      ERR_print_errors_fp( stdout );
      return 1;
#ifdef _DEBUG_OSSL_
   } else {
      fprintf( stdout, " [%s]  Loaded certificate file: \"%s\" \n",
               FUNC, certfile );
#endif
   }

#ifdef _DEBUG_OSSL_
   fprintf( stdout, " [%s]  Loading key: \"%s\" \n", FUNC, keyfile );
#endif
   ierr = SSL_CTX_use_PrivateKey_file( ctx, keyfile, SSL_FILETYPE_PEM );
   if( ierr <= 0 ) {
      fprintf( stdout, " [Error]  Could not load private key file: \'%s\"\n",
               keyfile );
      ERR_print_errors_fp( stdout );
      // unload certfile here?
      return 2;
#ifdef _DEBUG_OSSL_
   } else {
      fprintf( stdout, " [%s]  Loaded private key from file: \"%s\" \n",
               FUNC, keyfile );
#endif
   }

   // check for consistency of key and certificate
   if( !SSL_CTX_check_private_key( ctx ) ) {
      fprintf( stdout, " [Error]  Private key does not match the public certificate\n" );
      // unload certfile/privkey here?
      return 3;
#ifdef _DEBUG_OSSL_
   } else {
      fprintf( stdout, " [%s]  Private key matches certificate \n", FUNC );
#endif
   }

   return 0;
}


//
// Function to create an SSL "server"
//
// This function creates an SSL context by using select methods and loads the
// certificates that it needs to allow for the clients to perform verification
// of the server's identity. It loads the certificate and its key from files.
//

int inOSSL_CreateServerFromFiles( struct inOSSL_data_s *p,
                                  const char keyfile[], const char certfile[] )
{
#ifdef _DEBUG_OSSL_
   char FUNC[] = "inOSSL_CreateServerFromFiles";
   fprintf( stdout, " [%s]  Creating SSL server from files\n", FUNC );
   if( p->ca_cert == NULL ) {
      fprintf( stdout, " [%s]  The CA certificates file is null \n", FUNC );
   }
   if( p->ca_path == NULL ) {
      fprintf( stdout, " [%s]  The CA certificates path is null \n", FUNC );
   }
#endif
// p->method = SSLv2_server_method();
// p->method = SSLv3_server_method();
// p->method = TLSv1_server_method();
// p->method = TLSv1_1_server_method();
// p->method = TLSv1_2_server_method();
   p->method = TLS_server_method();

   p->sslctx = SSL_CTX_new( p->method );
   if( p->sslctx == NULL ) {
      fprintf( stdout, " [Error]  Could not create SSL server context\n" );
#ifdef _OUTPUT_OSSL_
      fprintf( stdout, " [%s]  Could not create SSL server context \n", FUNC );
      ERR_print_errors_fp( stdout );
#endif
      return 1;
#ifdef _DEBUG_OSSL_
   } else {
      fprintf( stdout, " [%s]  Created SSL server context \n", FUNC );
#endif
   }

   // verify locations where CA certificates for verification purposes are found
   if( SSL_CTX_load_verify_locations( p->sslctx, p->ca_cert, p->ca_path ) ) {
      fprintf( stdout, " [Error]  Could set CA verification file(s) path\n" );
#ifdef _OUTPUT_OSSL_
      fprintf( stdout, " [%s]  Could not verify CA file location \n", FUNC );
#endif
      SSL_CTX_free( p->sslctx );
      p->sslctx = NULL;
      return 2;
#ifdef _DEBUG_OSSL_
   } else {
      fprintf( stdout, " [%s]  Loaded trusted CA certificates \n", FUNC );
#endif
   }

   // prevent this version from being used (apparently due to security issues)
   SSL_CTX_set_options( p->sslctx, SSL_OP_NO_SSLv2 );

   // load certificate file and the server's private key
   int ierr = inOSSL_LoadCertificates( p->sslctx, certfile, keyfile );
   if( ierr != 0 ) {
      fprintf( stdout, " [Error]  Could not load CA certificate and key\n" );
      SSL_CTX_free( p->sslctx );
      p->sslctx = NULL;
      return 3;
#ifdef _DEBUG_OSSL_
   } else {
      fprintf( stdout, " [%s]  Loaded CA certificate and server key \n", FUNC );
#endif
   }

   return 0;
}


//
// Function to terminate and clean-up an SSL server context
// This is a clean-up function with little functionality...
//

int inOSSL_TerminateServer( struct inOSSL_data_s *p )
{
   // check for validity of SSL context and return error...
   if( p == NULL ) return 1;

   // terminate SSL context (possibly clean-up certificates?)
   SSL_CTX_free( p->sslctx );

   return 0;
}


//
// Function to retrieve the _peer's_ certificate(s)
//
// I do not know exactly what this function does, but it wants to look at only
// the peer's certificates and reports "NO certificate" if called by an SSL
// "server" setup; this is not a bad thing. (This is to be explored...)
//

X509* inOSSL_GetCertificate( SSL *ssl )
{
#ifdef _OUTPUT_OSSL_
   char FUNC[] = "inOSSL_GetCertificate";
#endif
   // get the certificate if it is available
   X509 *cert = SSL_get_peer_certificate( ssl );
   if( cert != NULL ) {
#ifdef _OUTPUT_OSSL_
      fprintf( stdout, " [%s]  Retrieved certificate from handle\n", FUNC );
#endif
   } else {
#ifdef _OUTPUT_OSSL_
      fprintf( stdout, " [%s]  No certificates in handle\n",  FUNC );
#endif
      return( NULL );
   }

   return( cert );
}


//
// Function to show a certificate
//
// This function shows the name, issuer and serial number of the certificate.
// It also checks if the certificate is a CA certificate and prints that info.
// (This function helps the user in knowing what is going on.)
//

void inOSSL_ShowCertificate( X509 *cert )
{
   char FUNC[] = "inOSSL_ShowCertificate";
   char *line;
   int raw;
   ASN1_INTEGER *serial;
   BIGNUM *bn;
   char *serial_ascii;

   if( cert == NULL ) {
      fprintf( stdout, " [%s]  Certificate pointer is null \n", FUNC );
      return;
   }

   fprintf( stdout, " [%s]  Server certificate:\n", FUNC );
   line = X509_NAME_oneline( X509_get_subject_name( cert ), NULL, 0 );
   fprintf( stdout, " [%s]  Subject: %s\n", FUNC, line );
   free( line );
   line = X509_NAME_oneline( X509_get_issuer_name( cert ), NULL, 0 );
   fprintf( stdout, " [%s]  Issuer: %s\n", FUNC, line );
   free( line );

   // get the certificate's serial number and display it 
   serial = X509_get_serialNumber(cert);  // get internal pointer; don't free
   bn = ASN1_INTEGER_to_BN(serial, NULL); // makes new BN object
   serial_ascii = BN_bn2dec(bn);          // get pointer to new char object
   BN_free( bn );                         // drop the big-number object
   fprintf( stdout, " [%s]  Certificate's serial num. \"%s\"\n",
            FUNC, serial_ascii );
   free( serial_ascii );                  // drop the string

   // provide some info about the certificate
   fprintf( stdout, " [%s]  ", FUNC );
   raw = X509_check_ca( cert );
/// Here is the manual page on what to expect:
///    Function return 0, if it is not CA certificate, 1 if it is proper
///    X509v3 CA certificate with basicConstraints extension CA:TRUE, 3, if it
///    is self-signed X509 v1 certificate, 4, if it is certificate with
///    keyUsage extension with bit keyCertSign set, but without
///    basicConstraints, and 5 if it has outdated Netscape Certificate Type
///    extension telling that it is CA certificate.
///    Actually, any non-zero value means that this certificate could have
///    been used to sign other certificates.
   if( raw == 0 ) {
      fprintf( stdout, "   This is not a CA certificate \n");
   } else if( raw == 1 ) {
      fprintf( stdout, "   This is an X.509 v3 CA certificate with basicConstraints extension CA:TRUE \n");
   } else if( raw == 3 ) {
      fprintf( stdout, "   This is a self-signed X.509 v1 certificate \n");
   } else if( raw == 4 ) {
      fprintf( stdout, "   This is a certificate with keyUsage extension with bit keyCertSign set, but without basicConstraints \n");
   } else if( raw == 5 ) {
      fprintf( stdout, "   This is a certificate with an outdated Netscape Certificate Type extension telling that it is a CA certificate \n");
   } else {
      fprintf( stdout, "   (Negative value) This is just unknown \n");
   }
}


//
// Function to show the result of certificate verification
//

void inOSSL_QueryVerifyResult( long result )
{
   fprintf( stdout, " Verification result is: " );

   if(        result == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT ) {
      fprintf( stdout, "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT \n" );
   } else if( result == X509_V_ERR_UNABLE_TO_GET_CRL ) {
      fprintf( stdout, "X509_V_ERR_UNABLE_TO_GET_CRL \n" );
   } else if( result == X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE ) {
      fprintf( stdout, "X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE \n" );
   } else if( result == X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE) {
      fprintf( stdout, "X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE \n" );
   } else if( result == X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY ) {
      fprintf( stdout, "X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY \n" );
   } else if( result == X509_V_ERR_CERT_SIGNATURE_FAILURE) {
      fprintf( stdout, "X509_V_ERR_CERT_SIGNATURE_FAILURE \n" );
   } else if( result == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ) {
      fprintf( stdout, "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY \n" );
   } else {
      fprintf( stdout, "UNKNOWN: %ld  \n", result );
   }

   fprintf( stdout, "\n" );
}


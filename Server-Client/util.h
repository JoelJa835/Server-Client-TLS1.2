#ifndef TLS_H
#define TLS_H

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <resolv.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>


int OpenConnection(const char *hostname, int port);
X509* accessCertificate(X509 *cert, char * path);
SSL_CTX* InitCTX(void);
SSL_CTX* InitServerCTX(void);
void ShowCerts(SSL* ssl);
int OpenListener(int port);
int isRoot();
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile);
void Servlet(SSL* ssl);

#endif
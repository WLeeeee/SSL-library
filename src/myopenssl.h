
#ifndef __MYOPENSSL_H_
#define __MYOPENSSL_H_

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "Common.h"

#define OPENSSL SSL

typedef struct myopssl {
	SSL * ssl_sess;
	SSL_CTX * ctx;
	X509 * cert;
	int connfd;
} MYOPSSL;


void initMyOpenssl();
void myopensslClean(MYOPSSL * ossl);
MYOPSSL * myopensslInitClient(int connfd, CmdTable * cmds, int which);

int myopensslHSK(OPENSSL * ossl);
int OpenListener(int port);
SSL_CTX* InitServerCTX(void);
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile);
void ShowCerts(SSL* ssl);
void Servlet(SSL* ssl);	/* Serve the connection -- threadable */

#endif


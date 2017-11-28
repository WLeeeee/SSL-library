#ifndef _SSL_SVR_H_
#define _SSL_SVR_H_

#define ACCEPT_LIMIT					1024

void sslSvrEnt(void *cmdTable);
void sslStdIOApp(SSLSession *ssl, int sslVer, int which,
						FILE *inLog, FILE *outLog);

#endif

#include "SSL.h"

/*
 * This function provides a secure method for communication with 
 * sender and receiver. Sender can use stdin to send the message 
 * and the result will be showed at the stdout of receiver. All
 * messages will be encrypted before sending.
 */
void sslStdIOApp(SSLSession *ssl, int sslVer, int which,
						FILE *inLog, FILE *outLog)
{
	fd_set rfds;
	//struct timeval tv;
	int retval; 
	u1 *ptr, *pData;
	int macLen = EVP_MD_size(ssl->cs->digest);
	
	printf("COMMUNICATION WITH %s STARTED\n", 
			which==SSL_CLIENT ? "SERVER":"CLIENT");
#define STDIN_LIMIT 4096

	while (true) {
		FD_ZERO(&rfds);
		FD_SET(STDIN_FILENO, &rfds);
		FD_SET(ssl->connfd, &rfds);
		
		retval = select(ssl->connfd+1, &rfds, NULL, NULL, NULL);
		/* Watch stdin and connfd to see when it has input. */
		if (retval == -1) {
			printf("Error while communication\n");
		} else if (retval) {
			if (FD_ISSET(STDIN_FILENO, &rfds)) {
				/* Something from STDIN needs to be sent */	
				int cipherLen = 0;

				pData = ptr = ssl->rawDataBuf + SSLRTHdrLen;
				ptr += readFD(STDIN_FILENO, 
							  ssl->rawDataBuf+SSLRTHdrLen, 
							  STDIN_LIMIT, NULL);

				if (which == SSL_SERVER)
					printf("Server said:");
				else
					printf("Client said:");

				int i;
				for (i=0; i<(ptr-pData); i++) {
					printf("%c", pData[i]);
				}
				if (strncmp((char *)pData, "R\n", 2) == 0) { 
					if (ssl->method->handshake(ssl, false) < 0) {
						printf("Re-negotiation failed\n");
						goto bail;
					}
				}
				cipherLen = sslSessionEnc(ssl, pData, 
										  ptr-pData, pData, 
										  SSL_RT_APPLICATION_DATA, 
										  sslVer, which);
				
				if (sslSendPacket(ssl, SSL_RT_APPLICATION_DATA, sslVer,
								  cipherLen, outLog) < 0)
				{
					printf("Application data sent Failed\n");
					goto bail;
				}
			} 
			if (FD_ISSET(ssl->connfd, &rfds)) {
				/* Something from socket needs to be received */
				int plainLen = 0;
				
				if (sslRecvPacket(ssl, SSL_RT_APPLICATION_DATA, 
								  sslVer, inLog) < 0)
				{
					break;
				}

				/* begin handling received messages */
				pData = ptr = ssl->rawDataBuf + SSLRTHdrLen;
				/*
				 * data decryption and MAC verification 
				 */
				plainLen = 
					sslSessionDec(ssl, ptr, ssl->rawDataLen, 
								  ptr, SSL_RT_APPLICATION_DATA, 
								  sslVer, which);

				if (which == SSL_CLIENT)
					printf("Server said:");
				else
					printf("Client said:");
				int i;
				for (i=0; i<(plainLen-macLen); i++) {
					printf("%c", pData[i]);
				}
			}
		} 
	}
bail:
	printf("COMMUNICATION WITH %s FINISHED\n", 
			which==SSL_CLIENT ? "SERVER":"CLIENT");
#undef INPUT_LIMIT
}
void sslSvrEnt(void *cmdTable)
{
	extern int errno;
	struct sockaddr_in saddr;
	int sockfd;
	SSLSession *ssl;
	CmdTable *cmds = (CmdTable *)cmdTable;
	
	if (cmds->port == 0) {
		printf("Listening port required\n");
		goto bail;
	}
	if (cmds->certPath == NULL) {
		printf("x509 certificate required\n");
		goto bail;
	}

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("opening socket error\n");
		goto bail;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(cmds->port);
	
	if(bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		printf("\nCould not connect to host\n");
		goto bail;
	}

	if(listen(sockfd, ACCEPT_LIMIT) < 0) {
		printf("\nCould not listen\n");
		goto bail;
	}

	bool shutdown = false;
	int saddrSize = sizeof(struct sockaddr_in);
	
	while (!shutdown) {
		printf("ACCEPT\n");
		int connfd = accept(sockfd, (struct sockaddr*) &saddr, 
							(socklen_t *) &saddrSize);
		
		if (connfd < 0) {
			printf("Can't accept client\n");
			continue;
		}
		struct sockaddr_in caddr;
		int caddrSize = saddrSize;
		getpeername(connfd, (struct sockaddr*) &caddr, 
					(socklen_t *) &caddrSize);

		/* fork a child server to serve client */
		pid_t pid;
		if ((pid = fork()) == 0) {
			
			if ((ssl = sslInit(connfd, cmds, SSL_SERVER)) == NULL) {
				goto child_finish;
			}
			/*
			 * By default, ssl methods will be set to TLS1.0(SSL3.1).
			 * Thus, method ptr will be reset to appropriate ssl 
			 * methods if client's preferred SSL version differs from
			 * server's version.
			 */
			ssl->method = s31SvrMeth();
			if (ssl->method->handshake(ssl, true) == 
				SSL_MT_HSK_SUCCESS) 
			{
				printf("HANDSHAKE SUCCESS\n");
				
				FILE *inLog = NULL;
				FILE *outLog = NULL;
#if defined(DEBUG)
				assert(SVRLOGDIR != NULL);
				char logName1[strlen("serverIn") + 
							  strlen(SVRLOGDIR) + 1];
				char logName2[strlen("serverOut") + 
							  strlen(SVRLOGDIR) + 1];
				sprintf(&logName1[0], "%sserverIn", SVRLOGDIR);
				sprintf(&logName2[0], "%sserverOut", SVRLOGDIR);
				inLog = fopen(logName1, "w+");
				outLog = fopen(logName2, "w+");
#endif
				sslStdIOApp(ssl, ssl->method->version(), SSL_SERVER, 
							inLog, outLog);
#if defined(DEBUG)
				if (inLog)
					fclose(inLog);
				if (outLog)
					fclose(outLog);
#endif
			} else {
				printf("HANDSHAKE FAILED\n");
				goto child_finish;
			}
		} else {
			printf("Accept client from %s at port %d\n", 
					inet_ntoa(caddr.sin_addr), 
					ntohs(caddr.sin_port));
		}
	}

child_finish:
	sslClean(ssl, ssl->connfd, SSL_SERVER);

bail:
	printf("SERVER EXIT\n");
}

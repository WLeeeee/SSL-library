#include "http.h"
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "../myopenssl.h"

#define CHECK_BLANK(idx, buf) \
	(buf[idx] == ' ' || buf[idx] == '\n' || buf[idx] == '\r')

/* socket buffer */
char sock_buf[4096] = {0};
/* http version:1.0 or 1.1 */
unsigned version;
/* Port number */
unsigned port_num;
/* 
 * Time out in second 
 * =0 for http 1.0
 * >0 for http 1.1
 */
unsigned timeout;

/* 400 Bad Request */
char content_400[] = 
"<html><head>\n<title>400 Bad Request</title>\n</head><body>\n"
"<h1>Bad Request</h1><p>The browser (or proxy) sent a request "
"that this server could not understand.</p>\n"
"</body></html>";

/* 403 forbidden */
char content_403[] = 
"<html><head>\n<title>403 - Forbidden</title>\n</head><body>\n"
"<h1>Forbidden</h1>"
"<p>You do not have permission to access the requested address (URL).</p>\n"
"</body></html>";

/* 404 not found content */
char content_404[] = 
"<html><head>\n<title>404 Not Found</title>\n</head><body>\n"
"<h1>Not Found</h1>\nThe requested URL was not found on this server.\n"
"</body></html>\n\0";

void error(char *err_msg)
{
	printf("%s", err_msg);
	exit(1);
}

void dump_buf(char *buf, int len, int file_size)
{
	int i, count, write_size = 1048576;
	int j;

	if (file_size >= write_size)
		count = 1;
	else
		count = write_size / file_size;

	for (j=0; j<len; j++) {
		fprintf(stderr, "%x ", (int)buf[j]);
	}
	fprintf(stderr, "\n");
}

int get_time(char *buf)
{
	time_t curtime;
	struct tm *loctime;
	int len;

	/* Get the current time. */
	curtime = time(NULL);

	/* Convert it to local time representation. */
	loctime = localtime(&curtime);

	/* Print out the date and time in the standard format. */
	len = sprintf(buf, "%s", asctime(loctime));

	/* asctime will put a '\n' at the end of string */
	buf[len-1] = '\n';
	buf[len] = '\0';

	return strlen(buf);
}

char *get_file_ext(char *filename) {
	char *e = strrchr(filename, '.');
	if (e == NULL)
		e = ""; 
	return e;
}

int get_200_ok(char *buf, char *file_ext, int file_len)
{
	int main_ver = 1;
	int minor_ver = 0;
	int cc = 0;

	if (version == 11)
		minor_ver = 1;

	cc += sprintf(buf, "HTTP/%d.%d 200 OK\n", main_ver, minor_ver);

	if (strcmp(file_ext, ".html") == 0) {
		cc += sprintf(&buf[cc], "Content-Type: text/html\n");
	} else if (strcmp(file_ext, ".jpeg") == 0 ||
			   strcmp(file_ext, ".jpg") == 0)
	{
		cc += sprintf(&buf[cc], "Content-Type: image/%s\n", file_ext);
	} else if (strcmp(file_ext, ".gif") == 0) {
		cc += sprintf(&buf[cc], "Content-Type: image/gif\n");
	} else if (strcmp(file_ext, ".ico") == 0) {
		cc += sprintf(&buf[cc], "Content-Type: image/x-icon\n");
	} else if (strcmp(file_ext, ".png") == 0) {
		cc += sprintf(&buf[cc], "Content-Type: image/x-icon\n");
	} else {
		fprintf(stderr, "ERROR:Undefined file extension %s\n", file_ext);
		error("");
	}
	
	cc += sprintf(&buf[cc], "Content-Length: %d\n", file_len);

	if (version == 10) {
		cc += sprintf(&buf[cc], "Connection: Close\n\n");
	} else {
		cc += sprintf(&buf[cc], "Keep-Alive: timeout=%d, max=%d\n",
				timeout, timeout);
		cc += sprintf(&buf[cc], "Connection: Keep-Alive\n\n");
	}

	return cc;
}

int get_400_bad_request(char *buf)
{
	int main_ver = 1;
	int minor_ver = 0;
	int cc = 0;

	cc += sprintf(buf, "HTTP/%d.%d 400 Bad Request\n", main_ver, minor_ver);
	cc += sprintf(&buf[cc], "Content-Length: %d\n", strlen(content_400));
	cc += sprintf(&buf[cc], "Connection: close\n");
	cc += sprintf(&buf[cc], "Content-Type: text/html\n\n");
	cc += sprintf(&buf[cc], "%s\0", content_400);
}

int get_403_forbidden(char *buf)
{
	int main_ver = 1;
	int minor_ver = 0;
	int cc = 0;

	cc += sprintf(buf, "HTTP/%d.%d 403 Forbidden\n", main_ver, minor_ver);
	cc += sprintf(&buf[cc], "Content-Length: %d\n", strlen(content_403));
	cc += sprintf(&buf[cc], "Connection: close\n");
	cc += sprintf(&buf[cc], "Content-Type: text/html\n\n");
	cc += sprintf(&buf[cc], "%s\0", content_403);
}

int get_404_not_found(char *buf)
{
	int main_ver = 1;
	int minor_ver = 0;
	int cc = 0;
	
	if (version == 11)
		minor_ver = 1;

	cc += sprintf(buf, "HTTP/%d.%d 404 Not Found\n", main_ver, minor_ver);
	cc += sprintf(&buf[cc], "Content-Length: %d\n", strlen(content_404));
	cc += sprintf(&buf[cc], "Connection: close\n");
	cc += sprintf(&buf[cc], "Content-Type: text/html\n\n");
	cc += sprintf(&buf[cc], "%s\0", content_404);

	return cc;
}

/* 
 * Try to read data from fd
 */
int try_read(int fd, char* read_buf, int read_len)
{
	int read_cnt;
	int offset;
	
	read_cnt = read(fd, (void *)read_buf, read_len);
	
	if (read_cnt < 0) {
		if (errno == EAGAIN)
			return 0;
		fprintf(stderr, "ERROR:Read error with errno=%d %d\n", errno, fd);
		fflush(stderr);
		return 0;
	}

	return read_cnt;
}

int try_write(int fd, char *write_buf, int write_len)
{
	int write_cnt;
	int offset;

	write_cnt = write(fd, (void *)write_buf, write_len);

	if (write_cnt != write_len) {
		if (errno == ECONNRESET)
			return 0;
		fprintf(stderr, "ERROR:Write error with errno=%d, "
			"write_cnt:%d != write_len:%d\n", errno, write_cnt, write_len);
		fflush(stderr);
		return 0;
	}

	return write_cnt;
}

int try_ssl_write(SSLSession *ssl, char *write_buf, int write_len)
{
	char *pData, *ptr;
	int cipherLen = 0;
	int sslVer = ssl->method->version();
	int wCount;

	pData = ptr = ssl->rawDataBuf + SSLRTHdrLen;

	memcpy(pData, write_buf, write_len);

	ptr += write_len;

	cipherLen = sslSessionEnc(ssl, pData, 
			ptr-pData, pData, 
			SSL_RT_APPLICATION_DATA, 
			sslVer, SSL_SERVER);

	if ((wCount = sslSendPacket(ssl, SSL_RT_APPLICATION_DATA, sslVer,
				cipherLen, NULL)) < 0)
	{
		error("Application data sent Failed\n");
	}
}

// openssl
int try_openssl_write(OPENSSL *ssl, char *write_buf, int write_len)
{
//    char *pData, *ptr;
//    int cipherLen = 0;
 
    if ( SSL_write(ssl, write_buf, write_len) < 0)
    {   
        error("Application data sent Failed\n");
    }   
}



void send_error(SSLSession *ssl, int cc, OPENSSL * ossl)
{
	char buf[512] = {0};

	if (cc < 400)
		return;

	switch (cc) {
		case 400:
			get_400_bad_request(buf);
			break;
		case 403:
			get_403_forbidden(buf);
			break;
		case 404:
			get_404_not_found(buf);
			break;
	}
	if(ossl != NULL) {
		try_openssl_write(ossl, buf, strlen(buf));
	} else {
		try_ssl_write(ssl, buf, strlen(buf));
	}
}

int open_file_for_write(char *filename, SSLSession *ssl, OPENSSL * ossl)
{
	int ffd;
	int file_size;
	char buf[1024] = {0};

	if (strcmp(filename, "./") == 0) {
		strcpy(filename, "./index.html");
	} 
	
	ffd = open(filename, O_RDONLY);

	if (ffd < 0) { /* Failed and send 404 */
		fprintf(stderr, "ERROR:Cannot open file %s, errno=%d\n", 
			filename, errno);
		if (errno == EACCES) {
			return -403;
		} else {
			return -404;
		}
	} 

	file_size = lseek(ffd, 0, SEEK_END);
	lseek(ffd, 0, SEEK_SET);

	/* Send 200 OK at first */
	get_200_ok(buf, get_file_ext(filename), file_size);
	if(ossl != NULL) {
		try_openssl_write(ossl, buf, strlen(buf));
	} else {
		try_ssl_write(ssl, buf, strlen(buf));
	}

	int total = 0;
	while (file_size) {
		int read_cnt = try_read(ffd, buf, sizeof(buf));
		total += read_cnt;

		if (read_cnt) {
			if(ossl != NULL) {
				if (try_openssl_write(ossl, buf, read_cnt) == 0) {
                    close(ffd);
                    return -1; 
                }	
			} else {
				if (try_ssl_write(ssl, buf, read_cnt) == 0) {
					close(ffd);
					return -1;
				}
			} // end of ossl switch
		}
		file_size -= read_cnt;
	}

	close(ffd);
	return 0;
}

int handle_get(char *path, char *cli_ver, SSLSession *ssl, OPENSSL * ossl)
{
	char buf[256];
	int state = 0;
	int idx = 0;

	/* Check and get file name */
	if (!path || *path != '/')
		return -400;

	sscanf(path, "%s", &buf[1]);
	buf[0] = '.';

	/* Check client version */
	if (!cli_ver || strlen(cli_ver) != 8 || 
		(strcmp(cli_ver, "HTTP/1.0") != 0 && strcmp(cli_ver, "HTTP/1.1")) != 0)
		return -400;

	/* Send response */
	if(ossl != NULL) {
		return open_file_for_write(buf, NULL, ossl);
	} else {
		return open_file_for_write(buf, ssl, NULL);
	}
}

int readHttpHdr(SSLSession *ssl)
{
	int read_cnt;
	int plainLen;
	int macLen = EVP_MD_size(ssl->cs->digest);
	int sslVer = ssl->method->version();
	int skBufIdx = 0;

	while (1) {
		char *ptr, *pData;
		
		read_cnt = sslRecvPacket(ssl, SSL_RT_APPLICATION_DATA, 
				sslVer, NULL);

		if (read_cnt <= 0) {
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
					sslVer, SSL_SERVER);

		memcpy(&sock_buf[skBufIdx], pData, plainLen - macLen);
		skBufIdx += plainLen - macLen;

		/* End of header */
		if (skBufIdx > 4 &&
			sock_buf[skBufIdx-4] == '\r' && sock_buf[skBufIdx-3] == '\n' &&
			sock_buf[skBufIdx-2] == '\r' && sock_buf[skBufIdx-1] == '\n')
			break;
	}
#ifndef NOOUTPUT
	printf("%s\n", sock_buf);
#endif

	return skBufIdx;
}

int readHttpHdr_openssl(OPENSSL *ssl)
{
    int read_cnt = 0;
    int plainLen;
    //int macLen = EVP_MD_size(ssl->cs->digest);
    //int sslVer = ssl->method->version();
    int skBufIdx = 0;
 
    while (1) {
        char *ptr, *pData;
         
        read_cnt = SSL_read(ssl, sock_buf+skBufIdx, 4096-skBufIdx);
 
        if (read_cnt <= 0) {
            break;
        }
 
        //skBufIdx += plainLen - macLen;
        skBufIdx += read_cnt;
 
        /* End of header */
        if (skBufIdx > 4 &&
            sock_buf[skBufIdx-4] == '\r' && sock_buf[skBufIdx-3] == '\n' &&
            sock_buf[skBufIdx-2] == '\r' && sock_buf[skBufIdx-1] == '\n')
            break;
    }   
 
#ifndef NOOUTPUT
    printf("%s\n", sock_buf);
#endif
 
    return skBufIdx;
}



/* Respond to client */
int serve_client(SSLSession *ssl)
{
	int get_request = 1; /* It should be 1 by default */
	int cc;

	while (1) {

		int hdrLen = readHttpHdr(ssl);
		char *p_req[3];

		if (hdrLen == 0)
			break;

		/* Get request, path, and version one by one */
		p_req[0] = strtok(sock_buf," \r\n");
		p_req[1] = strtok(NULL, " \r\n");
		p_req[2] = strtok(NULL, " \r\n");

		/* Process request */
		if (p_req[0] && strlen(p_req[0]) == 3 && 
			strcmp(p_req[0], "GET") == 0) 
		{
			if ((cc = handle_get(p_req[1], p_req[2], ssl, NULL)) < 0)
				goto bail;
		} else {
			cc = -400;
			goto bail;
		}
		
		if (version == 10)
			break;
	} 

	return 0;
bail:
	printf("Error condition code=%d\n", cc);
	send_error(ssl, 0-cc, NULL);
	return -1;
}

/* Respond to client -- openssl */
int serve_client_openssl(OPENSSL * ssl)
{
	int get_request = 1; /* It should be 1 by default */
	int cc;

	while (1) {

		//int hdrLen = readHttpHdr(ssl);
		int hdrLen = readHttpHdr_openssl(ssl);
        printf("---  %s: header content: %d \n %s \n", __func__, hdrLen, sock_buf);
		char *p_req[3];

		if (hdrLen == 0)
			break;

		/* Get request, path, and version one by one */
		p_req[0] = strtok(sock_buf," \r\n");
		p_req[1] = strtok(NULL, " \r\n");
		p_req[2] = strtok(NULL, " \r\n");

		/* Process request */
		if (p_req[0] && strlen(p_req[0]) == 3 && 
			strcmp(p_req[0], "GET") == 0) 
		{
			if ((cc = handle_get(p_req[1], p_req[2], NULL, ssl)) < 0) //openssl
				goto bail;
		} else {
			cc = -400;
			goto bail;
		}
		
		if (version == 10)
			break;
	} 

	return 0;
bail:
	printf("Error condition code=%d\n", cc);
	send_error(NULL, 0-cc, ssl);	//openssl
	return -1;
}



/* Server main function */
void run(CmdTable *cmds)
{
	int sfd, clilen, n;
	struct sockaddr_in serv_addr, cli_addr;

	sfd = socket(AF_INET, SOCK_STREAM, 0);
	
	if (sfd < 0)
		error("ERROR:Cannot open socket\n");

	bzero((char *) &serv_addr, sizeof(serv_addr));

	serv_addr.sin_port = htons(port_num);

	serv_addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(sfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR:Cannot bind\n");

	listen(sfd, SERVER_MAX_LISTEN);

	clilen = sizeof(cli_addr);

	signal(SIGCHLD, SIG_IGN);

	while (1) {
		pid_t pid;
		int newfd;

		newfd = accept(sfd, (struct sockaddr *) &cli_addr, &clilen);

		if (newfd < 0)
			error("ERROR:Cannot accept\n");

		
		pid = fork();
		
		if (pid < 0)
			error("ERROR:Cannot fork\n");

		/* Child process */
		if (pid == 0)  {
			struct timeval tv;
			//openssl work// SSLSession *ssl;

			/* Set timeout value */
			tv.tv_sec = timeout;  
			tv.tv_usec = 0; 
			setsockopt(newfd, SOL_SOCKET, SO_RCVTIMEO, 
				(char *)&tv, sizeof(struct timeval));

			close(sfd);


			if(cmds->modeOpenSSL) {
    	        MYOPSSL *ossl;
				printf("--- %i \n", newfd);
				ossl = (MYOPSSL*) (intptr_t) myopensslInit(newfd, cmds, SSL_SERVER);
				if (ossl == NULL) {		goto bail;	}
            	// Guess we are success here            
	            printf("----- Enter Servlet\n");
    	        if ( SSL_accept(ossl->ssl_sess) == (-1) )                  /* do SSL-protocol accept */
        	    {
            	    ERR_print_errors_fp(stderr);
                	goto bail;
	            } else {   
    	            ShowCerts(ossl->ssl_sess);                             /* get any certificates */
        	        //bytes = SSL_read(ssl, buf, sizeof(buf));    /* get request */
            	    serve_client_openssl(ossl->ssl_sess);  //
                	// TODO: clean work
					myopensslClean(ossl);
	            }



			} else{

			SSLSession *ssl;
			if ((ssl = sslInit(newfd, cmds, SSL_SERVER)) == NULL) {
				goto bail;
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
				serve_client(ssl);
				sslClean(ssl, ssl->connfd, SSL_SERVER);
				exit(0);
			} else {
				printf("HANDSHAKE FAILED\n");
				goto bail;
			}

			}	// end of openssl mode switching.
		} else {
#ifndef NOOUTPUT
			printf("Accept client=%s, port=%u, sockfd=%d\n",
					inet_ntoa(cli_addr.sin_addr),
					ntohs(cli_addr.sin_port),
					newfd);
#endif
			close(newfd);
		}
	}
bail:
	return;
}

void sslHttpSvrEnt(void *parm)
{
	CmdTable *pCmdTable = (CmdTable *) parm;

	version = pCmdTable->httpVer;
	port_num = pCmdTable->port;

	if (port_num < 1024 || port_num > 65536) {
		error("ERROR:Port number must lie between 1024 and 65536\n");
	}

	timeout = 10;

	/* Start server */
#ifndef NOOUTPUT
	printf("SSL HTTP SERVER START\n");
#endif
	run(pCmdTable);
#ifndef NOOUTPUT
	printf("SSL HTTP SERVER END\n");
#endif
}

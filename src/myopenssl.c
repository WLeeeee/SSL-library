/* myopenssl.c
 *
 * Some part of code referencing: ssl_server.c
 * Here is their GPL claim:
 * -------------------------------------------------------------------------
 * Copyright (c) 2000 Sean Walton and Macmillan Publishers.  Use may be in
 * whole or in part in accordance to the General Public License (GPL).
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
*/

#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "myopenssl.h"
#include "Common.h"
#define FAIL    -1

//SSL_CTX * g_ctx = NULL;
//X509 * g_cert = NULL;
//int g_conn_id = 0;
/* ------------------------------------------------------------------- 
 * Init of open ssl lib
 * ------------------------------------------------------------------- */
void initMyOpenssl()
{
    // Initialization of Open SSL
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms(); 
}

MYOPSSL * initMySslStruct()
{
	MYOPSSL * ptr;
	ptr = (MYOPSSL *) malloc(sizeof(MYOPSSL));
    ptr->ssl_sess = NULL;
	ptr->ctx = NULL;
    ptr->cert = NULL;
	ptr->connfd = 0;
	return ptr;
}
/* ------------------------------------------------------------------- 
 * Init of OPENSSL session
 * ------------------------------------------------------------------- */
MYOPSSL * myopensslInit(int connfd, CmdTable *cmds, int which)
{
//	initMyOpenssl();	// check
	SSL_library_init();
	initMyOpenssl();
	MYOPSSL * ptr = NULL;
	ptr = initMySslStruct();

	//printf("Alloc %i, %i\n", sizeof(MYOPSSL), ptr == NULL);
	SSL_CTX * p = InitServerCTX();
	//printf("load\n");
	ptr->ctx = p;
    LoadCertificates(ptr->ctx, cmds->certPath, cmds->certPath);

	// cipher test for client parameters.
    // 1: TLS_RSA_WITH_RC4_128_SHA                        
    // SSL_CTX_set_cipher_list(ptr->ctx, "RC4-SHA");     
    // 2: TLS_RSA_WITH_3DES_EDE_CBC_SHA                
    // SSL_CTX_set_cipher_list(ptr->ctx, "DES-CBC3-SHA");
    // 3: TLS_RSA_WITH_AES_256_CBC_SHA                 
    // SSL_CTX_set_cipher_list(ptr->ctx, "AES256-SHA");  
    // 4: TLS_RSA_WITH_CAMELLIA_128_CBC_SHA            
    //SSL_CTX_set_cipher_list(ptr->ctx, "CAMELLIA128-SHA"); 


	//printf("here... %i\n", ptr->ctx == NULL);
    ptr->ssl_sess = SSL_new(ptr->ctx);                             /* get new SSL state with context */
    //printf("here... %i\n", ptr->ssl_sess == NULL);



	int a = SSL_set_fd(ptr->ssl_sess, connfd);                        /* set connection socket to SSL state */
	//printf("a = %i\n", a);
    //printf("enable fd\n");
	ptr->connfd = connfd;
	return ptr;	// Need clean work...
}

void myopensslClean(MYOPSSL * ossl)
{
	if( ossl->ctx != NULL)
		SSL_CTX_free(ossl->ctx);

	if( ossl->ssl_sess != NULL)
		SSL_free(ossl->ssl_sess);

	if( ossl->cert != NULL)
		X509_free(ossl->cert);
	
	//close(connfd);		
	close(ossl->connfd);

	//free(ossl);
	//ossl = NULL;
}

extern short clnCipherList[2];

MYOPSSL * myopensslInitClient(int connfd, CmdTable * cmds, int which)
{
    SSL_library_init();
    initMyOpenssl();
    MYOPSSL * ossl = NULL;
	ossl = initMySslStruct();


    BIO               *outbio = NULL;
    X509_NAME       *certname = NULL;
    const SSL_METHOD *method;
 
    //certbio = BIO_new(BIO_s_file());
    outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

    /* ---------------------------------------------------------- *
     * initialize SSL library and register algorithms             *
     * ---------------------------------------------------------- */
    if(SSL_library_init() < 0)
    	BIO_printf(outbio, "Could not initialize the OpenSSL library !\n");

	/* ---------------------------------------------------------- *
	* Set SSLv2 client hello, also announce SSLv3 and TLSv1      *
   	* ---------------------------------------------------------- */
  	method = SSLv23_client_method();
	
	/* ---------------------------------------------------------- *
	 * Try to create a new SSL context                            *
   	 * ---------------------------------------------------------- */
  	if ( (ossl->ctx = SSL_CTX_new(method)) == NULL)
    	BIO_printf(outbio, "Unable to create a new SSL context structure.\n");

	/* ---------------------------------------------------------- *
     * Disabling SSLv2 will leave v3 and TSLv1 for negotiation    *
     * ---------------------------------------------------------- */
    SSL_CTX_set_options(ossl->ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3
		| SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2);

	#if(1)
	switch(clnCipherList[1])
	{
	default:
		printf("No cipher specified. Using TLS_RSA_WITH_RC4_128_SHA\n");
	case 0x05:
		// TLS_RSA_WITH_RC4_128_SHA
		SSL_CTX_set_cipher_list(ossl->ctx, "RC4-SHA");
		break;
	case 0x0A:
		// 2: TLS_RSA_WITH_3DES_EDE_CBC_SHA
		SSL_CTX_set_cipher_list(ossl->ctx, "DES-CBC3-SHA");
		break;
	case 0x35:
		// 3: TLS_RSA_WITH_AES_256_CBC_SHA
		SSL_CTX_set_cipher_list(ossl->ctx, "AES256-SHA");
		break;
	case 0x41:
		// 4: TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
		SSL_CTX_set_cipher_list(ossl->ctx, "CAMELLIA128-SHA");
		break;
	}
	#endif
 	ossl->ssl_sess = SSL_new(ossl->ctx);

	#if(0)	// check cipher type
	int i = 0; char * p;
    do{
        p = SSL_get_cipher_list(ossl->ssl_sess, i); 
        ++i;
        printf("cipher: %s\n", p); 
    }while(p != NULL);
	#endif


	SSL_set_fd(ossl->ssl_sess, connfd);
	ossl->connfd = connfd;

	/* ---------------------------------------------------------- */
	// Now entering handshade process
    if ( SSL_connect(ossl->ssl_sess) != 1 ) 
    {   
        BIO_printf(outbio, "Error: Could not build a SSL session to:.\n");
        return NULL; 
    } else {
        BIO_printf(outbio, "Successfully enabled SSL/TLS session to:.\n");
    }   

    /* ---------------------------------------------------------- *
    * Get the remote certificate into the X509 structure         *
    * ---------------------------------------------------------- */
	ossl->cert = SSL_get_peer_certificate(ossl->ssl_sess);
  	if (ossl->cert == NULL)
    	BIO_printf(outbio, "Error: Could not get a certificate from: .\n");
  	else {
    	//BIO_printf(outbio, "Retrieved the server's certificate from: .\n");
	}


	/* ---------------------------------------------------------- *
   	* extract various certificate information                    *
   	* -----------------------------------------------------------*/
  	certname = X509_NAME_new();
  	certname = X509_get_subject_name(ossl->cert);
     
  	/* ---------------------------------------------------------- *
   	* display the cert subject here                              *
   	* -----------------------------------------------------------*/
  	BIO_printf(outbio, "Displaying the certificate subject data:\n");
  	X509_NAME_print_ex(outbio, certname, 0, 0);
  	BIO_printf(outbio, "\n");

    return ossl;    // Need clean work...	
}




/*---------------------------------------------------------------------*/
/*--- InitServerCTX - initialize SSL server  and create context     ---*/
/*---------------------------------------------------------------------*/
SSL_CTX* InitServerCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;

    //OpenSSL_add_all_algorithms();       /* load & register all cryptos, etc. */
    //SSL_load_error_strings();           /* load all error messages */

    //method = SSLv3_server_method();     /* create new server-method instance */
    //method = TLS_server_method(); // only 1.0.2
    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);          /* create new context from method */

    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
	//printf("aa\n");

    // Set options
    long opt = SSL_CTX_get_options(ctx);
    opt |= SSL_OP_NO_SSLv2;
    opt |= SSL_OP_NO_SSLv3;
    //opt |= SSL_OP_NO_TLSv1;
	//opt |= SSL_OP_NO_TLSv1_1;
	//opt |= SSL_OP_NO_TLSv1_2;
    SSL_CTX_set_options(ctx, opt);

	//printf("aa %i\n", ctx != NULL);
    return ctx;
}



/*---------------------------------------------------------------------*/
/*--- LoadCertificates - load from files.                           ---*/
/*---------------------------------------------------------------------*/
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    printf("--- %s: %s, %s\n", __func__, CertFile, KeyFile);
    /* set the local certificate from CertFile */

    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {

        ERR_print_errors_fp(stderr);
        abort();
    }

    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* verify private key */

    if ( !SSL_CTX_check_private_key(ctx) )
    {

        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }

}


/*---------------------------------------------------------------------*/
/*--- ShowCerts - print out certificates.                           ---*/
/*---------------------------------------------------------------------*/

void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);   /* Get certificates (if available) */

    if ( cert != NULL )
    {

        printf("Server certificates:\n");

        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);

        printf("Subject: %s\n", line);

        free(line);

        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);

        printf("Issuer: %s\n", line);

        free(line);

        X509_free(cert);

    }

    else

        printf("No certificates.\n");

}



/*---------------------------------------------------------------------*/
/*--- Servlet - SSL servlet (contexts can be shared)                ---*/
/*---------------------------------------------------------------------*/

void Servlet(SSL* ssl)  /* Serve the connection -- threadable */

{   char buf[1024];

    char reply[1024];

    int sd, bytes;

    const char* HTMLecho="<html><body><pre>%s</pre></body></html>\n\n";


    printf("----- Enter Servlet\n");

    if ( SSL_accept(ssl) == FAIL )                  /* do SSL-protocol accept */

        ERR_print_errors_fp(stderr);

    else

    {

        ShowCerts(ssl);                             /* get any certificates */

        bytes = SSL_read(ssl, buf, sizeof(buf));    /* get request */

        if ( bytes > 0 )

        {

            buf[bytes] = 0;

            printf("Client msg: \"%s\"\n", buf);

            sprintf(reply, HTMLecho, buf);          /* construct reply */

            SSL_write(ssl, reply, strlen(reply));   /* send reply */

        }

        else

            ERR_print_errors_fp(stderr);

    }

    sd = SSL_get_fd(ssl);                           /* get socket connection */

    SSL_free(ssl);                                  /* release SSL state */

    close(sd);                                      /* close connection */

}



/*---------------------------------------------------------------------*/

/*--- main - create SSL socket server.                              ---*/

/*---------------------------------------------------------------------*/
#if(0)
int main(int count, char *strings[])

{   SSL_CTX *ctx;

    int server;

    char *portnum;



    if ( count != 2 )

    {

        printf("Usage: %s <portnum>\n", strings[0]);

        exit(0);

    }

    portnum = strings[1];

    ctx = InitServerCTX();                              /* initialize SSL */

    LoadCertificates(ctx, "newreq.pem", "newreq.pem");  /* load certs */

    server = OpenListener(atoi(portnum));               /* create server socket */

    while (1)

    {   struct sockaddr_in addr;

        int len = sizeof(addr);

        SSL *ssl;



        int client = accept(server, &addr, &len);       /* accept connection as usual */

        printf("Connection: %s:%d\n",

            inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        ssl = SSL_new(ctx);                             /* get new SSL state with context */

        SSL_set_fd(ssl, client);                        /* set connection socket to SSL state */

        Servlet(ssl);                                   /* service connection */

    }

    close(server);                                      /* close server socket */

    SSL_CTX_free(ctx);                                  /* release context */

}

#endif

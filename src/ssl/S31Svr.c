#include "SSL.h"

static CipherSuite *chooseCipherSuite(int candidates, u1 *ptr)
{
	int i;
	int cipherID = 0;
	bool chosen = false;
	CipherSuite *pCipher = NULL;
	
	for (i=0; i<candidates; i+=2) {
		readBE(ptr+i, &cipherID, 2);
		if (!chosen) {
			pCipher = getCipherByID(cipherID);
			if (pCipher != NULL && 
				pCipher->cipherCB != &EVP_enc_null) 
			{
				pCipher->digest = (EVP_MD *) pCipher->digestCB();
				pCipher->cipher = (EVP_CIPHER *) pCipher->cipherCB();
				chosen = true;
			}
		}
	}
#if defined(DEBUG)
	printf("Cipher ID=0x%x name=%s\n", pCipher->ID, pCipher->name);
#endif
#if defined(DEBUG)
	printf("Chosen cipher ID = %x, name = %s\n", pCipher->ID, pCipher->name);
#endif
	return pCipher;
}

static int s31SvrSendHR(SSLSession *ssl, int nextStep)
{
	FILE *logFile = NULL;
#if defined(DEBUG)
	assert(SVRLOGDIR != NULL);
	char logName[strlen("serverHelloRequest") + strlen(SVRLOGDIR) + 1];
	sprintf(&logName[0], "%sserverHelloRequest", SVRLOGDIR);
	logFile = fopen(logName, "w+");
#endif
	int cc = -1;

	int totalMsgLen = 
		sslWriteMTHdr(ssl, 0, SSL_MT_HSK_HELLO_REQUEST, SSL_VERSION);

	if (sslSendPacket(ssl, SSL_RT_HANDSHAKE, SSL_VERSION, 
					  totalMsgLen, logFile) < 0) 
	{
		printf("Hello Request Sent Failed\n");
		goto bail;
	}

	cc = nextStep;
bail:
#if defined(DEBUG)
	fclose(logFile);
#endif
	return cc;
}

static int s31SvrRecvCH(SSLSession *ssl, int nextStep)
{
	FILE *logFile = NULL;
#if defined(DEBUG)
	assert(SVRLOGDIR != NULL);
	char logName[strlen("clientHello") + strlen(SVRLOGDIR) + 1];
	sprintf(&logName[0], "%sclientHello", SVRLOGDIR);
	logFile = fopen(logName, "w+");
#endif
	int cc = -1;
	
	if (ssl->rawDataLen == 0) {
		if (sslRecvPacket(ssl, SSL_RT_HANDSHAKE, SSL_VERSION, 
						  logFile) < 0)
			goto bail;
	}

	int msgLen, msgVer;
	u1 *pMsg, *ptr;

	pMsg = ptr = sslReadMTHdr(ssl, &msgLen, SSL_MT_HSK_CLIENT_HELLO, 
							  SSL_VERSION);

	if (ptr == NULL) goto bail;

	ptr += readBE(ptr, &msgVer, 2);
	CHECK_VER(SSL_VERSION, msgVer, M, bail);
	
	ssl->clnRandom = (u1 *) malloc(sizeof(u1) * 32);
	ptr += readBuf(ptr, ssl->clnRandom, 32);

	ptr += readBE(ptr, &ssl->sIDLen, 1);
	
	/*
	 * TODO: support session resumption request from client
	 */
	ssl->sID = (char *) malloc(sizeof(char) * ssl->sIDLen);
	ptr += readBuf(ptr, ssl->sID, ssl->sIDLen);

	int csLen, cmpLen;
	ptr += readBE(ptr, &csLen, 2);

	if ((ssl->cs = chooseCipherSuite(csLen, ptr)) == NULL) {
		printf("No suitable cipher suite found\n");
		goto bail;
	}
	ptr += csLen;
	ptr += readBE(ptr, &cmpLen, 1);

	/* TODO: support compression algorithm */
	ptr += readBE(ptr, &ssl->compression, 1);

	/* TODO: handle re-negotiation extensions */
	if ((ptr - pMsg) < msgLen) {
		int extLen;
		ptr += readBE(ptr, &extLen, 2);
		ptr += extLen; // Currently, just ignore it
	}

	CHECK_READ(msgLen, (int)(ptr - pMsg), bail);
	
	cc = nextStep;
bail:
#if defined(DEBUG)
	fclose(logFile);
#endif
	return cc;
}

static int s31SvrSendSH(SSLSession *ssl, int nextStep)
{
	FILE *logFile = NULL;
#if defined(DEBUG)
	assert(SVRLOGDIR != NULL);
	char logName[strlen("serverHello") + strlen(SVRLOGDIR) + 1];
	sprintf(&logName[0], "%sserverHello", SVRLOGDIR);
	logFile = fopen(logName, "w+");
#endif
	int cc = -1;
	u1 *pMsg, *ptr;
	
	ssl->svrRandom = genRandom(32);
	
	pMsg = ptr = 
		ssl->rawDataBuf + SSLMsgBody; // point to message type version
	
	ptr += writeBE(ptr, SSL_VERSION, 2);
	ptr += writeArrBE(ptr, ssl->svrRandom, 1, 32);
	/* 
	 * TODO: session resumption 
	 * Currently, session ID must be zero
	 */
	ptr += writeBE(ptr, ssl->sIDLen, 1);
	ptr += ssl->sIDLen;

	ptr += writeBE(ptr, ssl->cs->ID, 2);
	ptr += writeBE(ptr, ssl->compression, 1);

	int totalMsgLen = 
		sslWriteMTHdr(ssl, (ptr-pMsg), SSL_MT_HSK_SERVER_HELLO, 
					  SSL_VERSION);

	if (sslSendPacket(ssl, SSL_RT_HANDSHAKE, SSL_VERSION, 
					  totalMsgLen, logFile) < 0) 
	{
		printf("Server Hello Sent Failed\n");
		goto bail;
	}
	
	cc = nextStep;
bail:
#if defined(DEBUG)
	fclose(logFile);
#endif
	return cc;
}

static int s31SvrSendCert(SSLSession *ssl, int nextStep)
{
	FILE *logFile = NULL;
#if defined(DEBUG)
	assert(SVRLOGDIR != NULL);
	char logName[strlen("serverCert") + strlen(SVRLOGDIR) + 1];
	sprintf(&logName[0], "%sserverCert", SVRLOGDIR);
	logFile = fopen(logName, "w+");
#endif
	int cc = -1;

	u1 *ptr, *pMsg;
	int certLen;

	pMsg = ptr = ssl->rawDataBuf + SSLMsgBody;

	/* 
	 * TODO: Make certificate more flexible
	 * Currently, only one certificate is supported 
	 */
	ptr += 6;
	certLen = i2d_X509(ssl->certX509, &ptr);
	writeBE(pMsg + 3, certLen, 3);
	writeBE(pMsg, certLen + 3, 3);

	int totalMsgLen = 
		sslWriteMTHdr(ssl, (ptr - pMsg), SSL_MT_HSK_CERTIFICATE, 
					  SSL_VERSION);
	
	if (sslSendPacket(ssl, SSL_RT_HANDSHAKE, SSL_VERSION, 
					  totalMsgLen, logFile) < 0) 
	{
		printf("Server certificate Sent Failed\n");
		goto bail;
	}
	
	cc = nextStep;
bail:
#if defined(DEBUG)
	fclose(logFile);
#endif
	return cc;
}

static int s31SvrSendSKE(SSLSession *ssl, int nextStep)
{
	FILE *logFile = NULL;
#if defined(DEBUG)
	assert(SVRLOGDIR != NULL);
	char logName[strlen("serverKeyExchange") + strlen(SVRLOGDIR) + 1];
	sprintf(&logName[0], "%sserverKeyExchange", SVRLOGDIR);
	logFile = fopen(logName, "w+");
#endif
	int cc = -1;

	u1 *ptr, *pMsg;
	RSA *oldRSA = NULL, *curRSA = NULL;

	pMsg = ptr = ssl->rawDataBuf + SSLMsgBody;
	curRSA = oldRSA = EVP_PKEY_get1_RSA(ssl->priKey);
	/*
	 * generate ephemeral new key pairs
	 */
	if (ssl->cs->isExport) {
		curRSA = RSA_generate_key(512, RSA_F4, NULL, NULL);
		EVP_PKEY_set1_RSA(ssl->priKey, curRSA);
	}
	int modLen, expLen, signLen;

	modLen = BN_bn2bin(curRSA->n, ptr+2);
	ptr += writeBE(ptr, modLen, 2);
	ptr += modLen;

	expLen = BN_bn2bin(curRSA->e, ptr+2);
	ptr += writeBE(ptr, expLen, 2);
	ptr += expLen;
	
	u1 svrHash[EVP_MAX_MD_SIZE];
	EVP_MD_CTX md5Ctx, sha1Ctx;
	u4 md5Len, sha1Len;

	EVP_MD_CTX_init(&md5Ctx);
	EVP_MD_CTX_init(&sha1Ctx);
	EVP_DigestInit_ex(&md5Ctx, EVP_md5(), NULL);
	EVP_DigestInit_ex(&sha1Ctx, EVP_sha1(), NULL);
	
	EVP_DigestUpdate(&md5Ctx, ssl->clnRandom, 32);
	EVP_DigestUpdate(&md5Ctx, ssl->svrRandom, 32);
	EVP_DigestUpdate(&md5Ctx, pMsg, ptr-pMsg);
	EVP_DigestFinal_ex(&md5Ctx, svrHash, &md5Len);
	EVP_MD_CTX_cleanup(&md5Ctx);

	EVP_DigestUpdate(&sha1Ctx, ssl->clnRandom, 32);
	EVP_DigestUpdate(&sha1Ctx, ssl->svrRandom, 32);
	EVP_DigestUpdate(&sha1Ctx, pMsg, ptr-pMsg);
	EVP_DigestFinal_ex(&sha1Ctx, svrHash+md5Len, &sha1Len);
	EVP_MD_CTX_cleanup(&sha1Ctx);

	signLen = RSA_private_encrypt(md5Len+sha1Len, svrHash, ptr+2, 
								  oldRSA, RSA_PKCS1_PADDING);

	ptr += writeBE(ptr, signLen, 2);
	ptr += signLen;

	int totalMsgLen = 
		sslWriteMTHdr(ssl, (ptr - pMsg), 
					  SSL_MT_HSK_SERVER_KEY_EXCHANGE, SSL_VERSION);
	
	if (sslSendPacket(ssl, SSL_RT_HANDSHAKE, SSL_VERSION, 
					  totalMsgLen, logFile) < 0) 
	{
		printf("Server certificate Sent Failed\n");
		goto bail;
	}
	cc = nextStep;
bail:
#if defined(DEBUG)
	fclose(logFile);
#endif
	/* old key has been changed to ephemeral key */
	if (oldRSA && (curRSA != oldRSA)) {
		RSA_free(oldRSA);
	}
	RSA_free(curRSA);

	return cc;
}

static int s31SvrSendSHD(SSLSession *ssl, int nextStep)
{
	FILE *logFile = NULL;
#if defined(DEBUG)
	assert(SVRLOGDIR != NULL);
	char logName[strlen("serverHelloDone") + strlen(SVRLOGDIR) + 1];
	sprintf(&logName[0], "%sserverHelloDone", SVRLOGDIR);
	logFile = fopen(logName, "w+");
#endif
	int cc = -1;

	int totalMsgLen =
		sslWriteMTHdr(ssl, 0, SSL_MT_HSK_SERVER_DONE, SSL_VERSION);

	if (sslSendPacket(ssl, SSL_RT_HANDSHAKE, SSL_VERSION, 
					  totalMsgLen, logFile) < 0) 
	{
		printf("Server Hello Done Sent Failed\n");
		goto bail;
	}
	
	cc = nextStep;
bail:
#if defined(DEBUG)
	fclose(logFile);
#endif
	return cc;
}

static int s31SvrRecvCKE(SSLSession *ssl, int nextStep)
{
	FILE *logFile = NULL;
#if defined(DEBUG)
	assert(SVRLOGDIR != NULL);
	char logName[strlen("clientKeyExchange") + strlen(SVRLOGDIR) + 1];
	sprintf(&logName[0], "%sclientKeyExchange", SVRLOGDIR);
	logFile = fopen(logName, "w+");
#endif
	int cc = -1;

	if (ssl->rawDataLen == 0) {
		if (sslRecvPacket(ssl, SSL_RT_HANDSHAKE, SSL_VERSION, 
						  logFile) < 0)
			goto bail;
	}

	int msgLen;
	u1 *ptr, *pMsg;

	pMsg = ptr = 
		sslReadMTHdr(ssl, &msgLen, SSL_MT_HSK_CLIENT_KEY_EXCHANGE, 
					 SSL_VERSION);

	if (ptr == NULL) goto bail;
	
	int cipherLen;
	RSA *rsa = EVP_PKEY_get1_RSA(ssl->priKey);
	
	ptr += readBE(ptr, &cipherLen, 2);
	if (cipherLen != RSA_size(rsa)) {
		printf("Inconsistent cipher text length\n");
		goto bail;
	}

	u1 preMS[PRE_MASTER_SECRET_SIZE] = {0};

	if (RSA_private_decrypt(RSA_size(rsa), ptr, 
						    preMS, rsa, RSA_PKCS1_PADDING) != 
		PRE_MASTER_SECRET_SIZE) 
	{
		printf("pre master secret decryption error\n");
		goto bail;
	}
	ssl->masterSecret = genMasterSecret(ssl, preMS, SSL_VERSION);
	ssl->keys = genKeyPairs(ssl, SSL_VERSION);

	ptr += cipherLen;
	
	cc = nextStep;
bail:
#if defined(DEBUG)
	fclose(logFile);
#endif
	RSA_free(rsa);
	return cc;
}

static int s31SvrRecvFIN(SSLSession *ssl, int nextStep)
{
	FILE *logFile1 = NULL;
	FILE *logFile2 = NULL;
#if defined(DEBUG)
	assert(CLNLOGDIR != NULL);
	char logName1[strlen("clientCCS") + strlen(CLNLOGDIR) + 1];
	char logName2[strlen("clientFinished") + strlen(CLNLOGDIR) + 1];
	sprintf(&logName1[0], "%sclientCCS", CLNLOGDIR);
	sprintf(&logName2[0], "%sclientFinished", CLNLOGDIR);
	logFile1 = fopen(logName1, "w+");
	logFile2 = fopen(logName2, "w+");
#endif
	int cc = -1;

	/* If all raw data are processed, reads new packet from socket */
	if (ssl->rawDataLen == 0) {
		if (sslRecvPacket(ssl, SSL_RT_CHANGE_CIPHER_SPEC, SSL_VERSION,
						  logFile1) < 0)
			goto bail;
	}
	u1 *ptr;
	int msgLen;
	
	/* 
	 * Receive ChangeCipherSpec
	 */
	ptr = sslReadMTHdr(ssl, NULL, SSL_MT_CCS, SSL_VERSION);

	if (ptr == NULL) goto bail;
	
	/* Receive Finished */
	if (ssl->rawDataLen == 0) {
		if (sslRecvPacket(ssl, SSL_RT_HANDSHAKE, SSL_VERSION, 
						  logFile2) < 0)
			goto bail;
	}
	/* points to encrypted cipher text */
	ptr = ssl->rawDataBuf + SSLMTHdr;
	
	u1 verifyData[TLS_VERIFY_DATA_SIZE];
	int plainLen = 0;

	/* decryption */
	EVP_DecryptInit_ex(ssl->cipherRCtx, 
					   (const EVP_CIPHER *)ssl->cs->cipher, NULL,
					   ssl->keys->clientW, ssl->keys->clientIV);
	EVP_CIPHER_CTX_set_padding(ssl->cipherRCtx, false);
	
	plainLen = 
		sslSessionDec(ssl, ptr, ssl->rawDataLen, ptr, 
					  SSL_RT_HANDSHAKE, SSL_VERSION, SSL_SERVER);

	if (plainLen < 0) {
		printf("decryption failed\n");
		goto bail;
	}

	genFinMsg(ssl, (u1 *)TLS_CLIENT_FINISH_CONST, 
			  TLS_CLIENT_FINISH_CONST_SIZE, verifyData, 
			  TLS_VERIFY_DATA_SIZE, SSL_VERSION);
	ptr = 
		sslReadMTHdr(ssl, &msgLen, SSL_MT_HSK_FINISHED, SSL_VERSION);

	if (ptr == NULL) goto bail;
	
	CHECK_READ(TLS_VERIFY_DATA_SIZE, msgLen, bail);
	
	/* handshake message verification */
	if (memcmp(verifyData, ptr, TLS_VERIFY_DATA_SIZE) != 0) 
	{
		printf("handshake message verification failed\n");
		goto bail;
	}
	
	/*
	 * Because ssl->rawDataLen is the length of cipher text, it is set
	 * to zero easily if the cipher text can be decrypted by server.
	 */
	ssl->rawDataLen = 0;
	
	cc = nextStep;
bail:
#if defined(DEBUG)
	fclose(logFile1);
	fclose(logFile2);
#endif
	return cc;
}

static int s31SvrSendFIN(SSLSession *ssl, int nextStep)
{
	FILE *logFile1 = NULL;
	FILE *logFile2 = NULL;
#if defined(DEBUG)
	assert(CLNLOGDIR != NULL);
	char logName1[strlen("serverCCS") + strlen(CLNLOGDIR) + 1];
	char logName2[strlen("serverFinished") + strlen(CLNLOGDIR) + 1];
	sprintf(&logName1[0], "%sserverCCS", CLNLOGDIR);
	sprintf(&logName2[0], "%sserverFinished", CLNLOGDIR);
	logFile1 = fopen(logName1, "w+");
	logFile2 = fopen(logName2, "w+");
#endif
	int cc = -1;

	u1 *ptr; 
	
	/* 
	 * Send ChangeCipherSpec
	 */
	writeBE(ssl->rawDataBuf + SSLMTHdr, SSL_MT_CCS, 1);

	if (sslSendPacket(ssl, SSL_RT_CHANGE_CIPHER_SPEC, SSL_VERSION, 
					  1, logFile1) < 0)
	{
		printf("ClientKeyExchange sent Failed\n");
		goto bail;
	}
	
	/* 
	 * Send Finished
	 */
	int plainLen;

	ptr = ssl->rawDataBuf + SSLMsgBody; // point to data directly

	genFinMsg(ssl, (u1 *)TLS_SERVER_FINISH_CONST, 
			  TLS_SERVER_FINISH_CONST_SIZE, ptr, 
			  TLS_VERIFY_DATA_SIZE, SSL_VERSION);

	plainLen = sslWriteMTHdr(ssl, TLS_VERIFY_DATA_SIZE, 
							 SSL_MT_HSK_FINISHED, SSL_VERSION);
	
	/* Client initialize cipher context for encryption */
	EVP_EncryptInit_ex(ssl->cipherWCtx, 
					   (const EVP_CIPHER *)ssl->cs->cipher, NULL,
					   ssl->keys->serverW, ssl->keys->serverIV);
	EVP_CIPHER_CTX_set_padding(ssl->cipherWCtx, false);
	
	int cipherLen;

	/* 
	 * Make ptr points to message header, then encrypt plain 
	 * text begins at ptr, and write result to the same address.
	 */
	ptr = ssl->rawDataBuf + SSLMTHdr;
	cipherLen = 
		sslSessionEnc(ssl, ptr, plainLen, ptr, 
					  SSL_RT_HANDSHAKE, SSL_VERSION, SSL_SERVER);

	if (sslSendPacket(ssl, SSL_RT_HANDSHAKE, SSL_VERSION, 
					  cipherLen, logFile2) < 0) 
	{
		printf("Server finished sent Failed\n");
		goto bail;
	}
	
	cc = nextStep;
bail:

#if defined(DEBUG)
	fclose(logFile1);
	fclose(logFile2);
#endif
	return cc;
}

/*
 * Server do handshake
 */
static int s31SvrHSK(SSLSession *ssl, bool isFirst)
{
	/*
	 * step description:
	 * 
	 * step >=  0  -> switch to next step number and execute
	 * step == -1  -> abnormal finish
	 * step == SSL_MT_HSK_SUCCESS -> handshake success
	 */
	int step = isFirst, nextStep;
	int finSR;
	bool sessionResumed = false;
	
	while (step >= 0 && step != SSL_MT_HSK_SUCCESS) {
		switch(step) {
			case SSL_MT_HSK_HELLO_REQUEST:
				nextStep = SSL_MT_HSK_CLIENT_HELLO;
				step = s31SvrSendHR(ssl, nextStep);
				break;
			case SSL_MT_HSK_CLIENT_HELLO: /* Receive ClientHello */
				nextStep = SSL_MT_HSK_SERVER_HELLO;
				step = s31SvrRecvCH(ssl, nextStep);
				break;
			case SSL_MT_HSK_SERVER_HELLO: /* Send ServerHello */
				nextStep = SSL_MT_HSK_CERTIFICATE;
				step = s31SvrSendSH(ssl, nextStep);
				break;
			case SSL_MT_HSK_CERTIFICATE: /* Send certificate */
				if (ssl->cs->isExport)
					nextStep = SSL_MT_HSK_SERVER_KEY_EXCHANGE;
				else 
					nextStep = SSL_MT_HSK_SERVER_DONE;

				step = s31SvrSendCert(ssl, nextStep);
				break;
			case SSL_MT_HSK_SERVER_KEY_EXCHANGE:
				nextStep = SSL_MT_HSK_SERVER_DONE;
				step = s31SvrSendSKE(ssl, nextStep);
				break;
			case SSL_MT_HSK_CERTIFICATE_REQUEST:
				break;
			case SSL_MT_HSK_SERVER_DONE: /* Send ServerHelloDone */
				nextStep = SSL_MT_HSK_CLIENT_KEY_EXCHANGE;
				step = s31SvrSendSHD(ssl, nextStep);
				break;
			case SSL_MT_HSK_CERTIFICATE_VERIFY:
				break;
			case SSL_MT_HSK_CLIENT_KEY_EXCHANGE: /* Receive ClientKeyExchange */
				nextStep = SSL_MT_HSK_FINISHED;
				step = s31SvrRecvCKE(ssl, nextStep);
				finSR = 2;
				break;
			case SSL_MT_HSK_FINISHED:
				if (finSR == 1) {		// send
					if (sessionResumed) {
						finSR = 2;
					} else {
						nextStep = SSL_MT_HSK_SUCCESS;
					}
					step = s31SvrSendFIN(ssl, nextStep);
				} else if (finSR == 2){	// receive
					if (sessionResumed) {
						nextStep = SSL_MT_HSK_SUCCESS;
					} else {
						finSR = 1;
					}
					step = s31SvrRecvFIN(ssl, nextStep);
				} else {				//un-defined

				}
				break;
		}
	}	

	return step;
}

static int s31Version()
{
	return SSL_VERSION;
}

SSL_METH svrMeth = {
	s31SvrHSK,
	s31Version,
};

SSL_METH* s31SvrMeth()
{
	return &svrMeth; 
}

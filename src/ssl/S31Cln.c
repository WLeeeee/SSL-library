#include "SSL.h"

SSLSession *ssl;
short clnCipherList[2] = {1, 0x2F};

/*
 * Send client hello to server
 */
static int s31ClnSendCH(int nextStep)
{
	FILE *logFile = NULL;
#if defined(DEBUG)
	assert(CLNLOGDIR != NULL);
	char logName[strlen("clientHello") + strlen(CLNLOGDIR) + 1];
	sprintf(&logName[0], "%sclientHello", CLNLOGDIR);
	logFile = fopen(logName, "w+");
#endif
	int cc = -1;
	ssl->clnRandom = genRandom(32);

	u1 *pData, *ptr;

	pData = ptr = 
		ssl->rawDataBuf + SSLMsgBody; // point to message type version

	ptr += writeBE(ptr, SSL_VERSION, 2);
	ptr += writeArrBE(ptr, ssl->clnRandom, 1, 32);
	/* 
	 * TODO: session resumption 
	 * Currently, session ID must be zero
	 */
	ptr += writeBE(ptr, ssl->sIDLen, 1);
	ptr += ssl->sIDLen;
	/*
	 * TODO: generate usable cipher suite list
	 * Currently, cipher list is hard coded
	 */
	//short cipherList[2]; = {4, 0x05, 0x0A, 0x2F, 0x41};
	//short cipherList[] = {5, 0x01, 0x02, 0x03, 0x04, 0x05};

	ptr += writeBE(ptr, clnCipherList[0] * 2, 2);
	ptr += writeArrBE(ptr, (u1 *)&clnCipherList[1], 2, clnCipherList[0]);	
	/* No compression method used */
	ptr += writeBE(ptr, 0x0100, 2);

	writeBE(ssl->rawDataBuf + SSLMTLen, ptr-pData, 3);
	writeBE(ssl->rawDataBuf + SSLMTHdr, SSL_MT_HSK_CLIENT_HELLO, 1);

	if (sslSendPacket(ssl, SSL_RT_HANDSHAKE, SSL_VERSION, 
					  (ptr-pData)+SSLMTHdrLen, logFile) < 0) 
	{
		printf("Client Hello Sent Failed\n");
		goto bail;
	}

	FIN_DIGEST_UPDATE(ssl->rawDataBuf + SSLMTHdr,
					  (ptr-pData)+SSLMTHdrLen);
	
	cc = nextStep;
bail:
#if defined(DEBUG)
	fclose(logFile);
#endif
	return cc;
}

static int s31ClnRecvSH(int nextStep)
{
	FILE *logFile = NULL;
#if defined(DEBUG)
	assert(CLNLOGDIR != NULL);
	char logName[strlen("serverHello") + strlen(CLNLOGDIR) + 1];
	sprintf(&logName[0], "%sserverHello", CLNLOGDIR);
	logFile = fopen(logName, "w+");
#endif
	int cc = -1;
	
	/* If all raw data are processed, reads new packet from socket */
	if (ssl->rawDataLen == 0) {
		if (sslRecvPacket(ssl, SSL_RT_HANDSHAKE, SSL_VERSION, 
						  logFile) < 0)
			goto bail;
	}

	int msgHdr, msgVer, msgLen;
	int cipherSuite;

	u1 *pMsgHdr, *ptr;
	
	/* point to message header */
	pMsgHdr = ptr = 
			ssl->rawDataBuf + SSLRTHdrLen + ssl->rawDataRead;

	/* Start processing message */
	ptr += readBE(ptr, &msgHdr, 1);
	CHECK_HDR(SSL_MT_HSK_SERVER_HELLO, msgHdr, M, bail);
	
	ptr += readBE(ptr, &msgLen, 3);
	
	ptr += readBE(ptr, &msgVer, 2);
	CHECK_VER(SSL_VERSION, msgVer, M, bail);

	ssl->svrRandom = (u1 *) malloc(sizeof(u1) * 32);
	ptr += readBuf(ptr, ssl->svrRandom, 32);

	ptr += readBE(ptr, &ssl->sIDLen, 1);
	
	ssl->sID = (char *) malloc(sizeof(char) * ssl->sIDLen);
	ptr += readBuf(ptr, ssl->sID, ssl->sIDLen);

	ptr += readBE(ptr, &cipherSuite, 2);

	ssl->cs = getCipherByID(cipherSuite);
	ssl->cs->digest = (EVP_MD *) ssl->cs->digestCB();
	ssl->cs->cipher = (EVP_CIPHER *) ssl->cs->cipherCB();

	ptr += readBE(ptr, &ssl->compression, 1);

	ssl->rawDataRead +=	(ptr - pMsgHdr);
	ssl->rawDataLen -= ssl->rawDataRead;

	FIN_DIGEST_UPDATE(ssl->rawDataBuf + SSLMTHdr,
					  ptr-pMsgHdr);
	
	cc = nextStep;
bail:
#if defined(DEBUG)
	fclose(logFile);
#endif
	return cc;
}

/* 
 * Receive server's certificate and verify it by using 
 * server's public key.
 * TODO: Don't use openssl library
 */
static int s31ClnVerifyCert(int nextStep)
{
	FILE *logFile = NULL;
#if defined(DEBUG)
	assert(CLNLOGDIR != NULL);
	char logName[strlen("serverCert") + strlen(CLNLOGDIR) + 1];
	sprintf(&logName[0], "%sserverCert", CLNLOGDIR);
	logFile = fopen(logName, "w+");
#endif
	int cc = -1;
	u1 *pTBSCert = NULL;

	/* If all raw data are processed, reads new packet from socket */
	if (ssl->rawDataLen == 0) {
		if (sslRecvPacket(ssl, SSL_RT_HANDSHAKE, SSL_VERSION, 
						  logFile) < 0)
			goto bail;
	}
	u1 *pMsgHdr, *ptr;
	/* Assume server & client use SHA-1 & PKCS#1 to sign the hash */
	u1 svrHash[35], clnHash[20];
	
	/* point to message header */
	pMsgHdr = ptr = 
			ssl->rawDataBuf + SSLRTHdrLen + ssl->rawDataRead;

	int msgHdr, certLen;
	/* Start processing message */
	ptr += readBE(ptr, &msgHdr, 1);
	CHECK_HDR(SSL_MT_HSK_CERTIFICATE, msgHdr, M, bail);

	ptr += 6;	// ignore message length & cert chain length
	ptr += readBE(ptr, &certLen, 3);

	/* 
	 *  Get TBSCertificate message for digest & generate SHA1
	 *  FIXME: modify it for flexibility at later time
	 */
	int TBSCertLen = 0;
	readBE(ptr + 6, &TBSCertLen, 2);
	TBSCertLen += 4; //include TBSCertificate DER header
	pTBSCert = (u1 *) malloc(sizeof(u1) * TBSCertLen);
	memcpy(pTBSCert, ptr+4, TBSCertLen);
	SHA1(pTBSCert, TBSCertLen, clnHash); // 20-bytes SHA-1 hash

	/* Get X509 certificate */
	ssl->certX509 = d2i_X509(NULL, (const unsigned char **)&ptr, certLen);
	ssl->pubKey = X509_get_pubkey(ssl->certX509);
	RSA *rsa = EVP_PKEY_get1_RSA(ssl->pubKey);
		
/*	if ((RSA_public_decrypt(RSA_size(rsa), ptr-0x80, 
							svrHash, rsa, RSA_PKCS1_PADDING)) != 35) 
	{
		printf("Signature decryption error by server's public key\n");
		goto bail;
	}
*/	/* hash comparison */
//	int i;
//	for (i=0; i<20; i++) {
		/* server's address plus 15 for omitting PKCS#1 header */
/*		if (svrHash[i+15] != clnHash[i]) {
			printf("Inconsistent hash value, certificate verify failed\n");
			goto bail;
		}
	}*/
	ssl->rawDataRead +=	(ptr - pMsgHdr);
	ssl->rawDataLen -= ssl->rawDataRead;
	/* Verification success */
	
	FIN_DIGEST_UPDATE(ssl->rawDataBuf + SSLMTHdr, ptr-pMsgHdr);
	
	cc = nextStep;
bail:
#if defined(DEBUG)
	fclose(logFile);
#endif
	if (pTBSCert != NULL)
		free(pTBSCert);
	return cc;
}

/* 
 * Receive ServerHelloDone
 */
static int s31ClnRecvSHD(int nextStep)
{
	FILE *logFile = NULL;
#if defined(DEBUG)
	assert(CLNLOGDIR != NULL);
	char logName[strlen("serverHelloDone") + strlen(CLNLOGDIR) + 1];
	sprintf(&logName[0], "%sserverHelloDone", CLNLOGDIR);
	logFile = fopen(logName, "w+");
#endif
	int cc = -1;

	/* If all raw data are processed, reads new packet from socket */
	if (ssl->rawDataLen == 0) {
		if (sslRecvPacket(ssl, SSL_RT_HANDSHAKE, SSL_VERSION, 
						  logFile) < 0)
			goto bail;
	}
	u1 *pMsgHdr, *ptr;
	
	/* point to message header */
	pMsgHdr = ptr = 
			ssl->rawDataBuf + SSLRTHdrLen + ssl->rawDataRead;

	int msgHdr;
	/* Start processing message */
	ptr += readBE(ptr, &msgHdr, 1);
	CHECK_HDR(SSL_MT_HSK_SERVER_DONE, msgHdr, M, bail);

	ptr += 3; // ignore messge length

	ssl->rawDataRead +=	(ptr - pMsgHdr);
	ssl->rawDataLen -= ssl->rawDataRead;

	FIN_DIGEST_UPDATE(ssl->rawDataBuf + SSLMTHdr, ptr-pMsgHdr);
	
	cc = nextStep;
bail:
#if defined(DEBUG)
	fclose(logFile);
#endif
	return cc;
}

/* 
 * Receive ServerKeyExchange
 * TODO: Assume we are using RSA key exchange algorithm, modify
 *        this constraint for more flexibility.
 */
static int s31ClnRecvSKE(int nextStep)
{
	FILE *logFile = NULL;
#if defined(DEBUG)
	assert(CLNLOGDIR != NULL);
	char logName[strlen("serverKeyExchange") + strlen(CLNLOGDIR) + 1];
	sprintf(&logName[0], "%sserverKeyExchange", CLNLOGDIR);
	logFile = fopen(logName, "w+");
#endif
	int cc = -1;
	int modLen, expLen, signLen;
	u1 *pEphMod = NULL, *pEphExp = NULL, *pSign = NULL;

#define USE_EPH_KEY(_keyLen, _cipherSuite) \
	(((_keyLen) > 64) || _cipherSuite->isExport)

	/* If all raw data are processed, reads new packet from socket */
	if (ssl->rawDataLen == 0) {
		if (sslRecvPacket(ssl, SSL_RT_HANDSHAKE, SSL_VERSION, 
						  logFile) < 0)
			goto bail;
	}
	u1 *pMsgHdr = NULL, *ptr = NULL;
	
	/* point to message header */
	pMsgHdr = ptr = 
			ssl->rawDataBuf + SSLRTHdrLen + ssl->rawDataRead;

	int msgHdr;
	/* Start processing message */
	ptr += readBE(ptr, &msgHdr, 1);
	CHECK_HDR(SSL_MT_HSK_SERVER_KEY_EXCHANGE, msgHdr, M, bail);
	ptr += 3; // omit message length

	/* new modulus */
	ptr += readBE(ptr, &modLen, 2);
	pEphMod = (u1 *) malloc(sizeof(u1) * modLen);
	ptr += writeArrBE(pEphMod, ptr, 1, modLen);

	/* new exponent */
	ptr += readBE(ptr, &expLen, 2);
	pEphExp = (u1 *) malloc(sizeof(u1) * expLen);
	ptr += writeArrBE(pEphExp, ptr, 1, expLen);

	/* verify the signature signed by server */
	RSA *rsa;
	u1 svrHash[36];
	
	ptr += readBE(ptr, &signLen, 2);
	pSign = (u1 *) malloc(sizeof(u1) * signLen);
	ptr += writeArrBE(pSign, ptr, 1, signLen);
	rsa = EVP_PKEY_get1_RSA(ssl->pubKey);
	if ((signLen > RSA_size(rsa)) || 
		(RSA_public_decrypt(signLen, pSign, svrHash, 
						   rsa, RSA_PKCS1_PADDING) != 36))
	{
		printf("Signature decryption error by server's public key\n");
		goto bail;
	}

	/* 
	 * change the old permanent public key in pkey 
	 * to new emphemeral public key
	 */
	if (USE_EPH_KEY(modLen, ssl->cs)) {
		RSA *newRSA = RSA_new();
		newRSA->n = BN_bin2bn(pEphMod, modLen, newRSA->n);
		newRSA->e = BN_bin2bn(pEphExp, expLen, newRSA->e);
		EVP_PKEY_set1_RSA(ssl->pubKey, newRSA);
		RSA_free(rsa);
	}

	{
		int i;
		for (i=0; i<36; i++) {
			printf("%x ", svrHash[i]);
		}
		printf("\n");
		
		unsigned int mdLen;
		unsigned char myHash[36];
		EVP_MD_CTX mdctx;

		EVP_MD_CTX_init(&mdctx);
		EVP_DigestInit_ex(&mdctx, EVP_md5(), NULL);
		EVP_DigestUpdate(&mdctx, ssl->clnRandom, 32);
		EVP_DigestUpdate(&mdctx, ssl->svrRandom, 32);
		EVP_DigestUpdate(&mdctx, pMsgHdr+4, ptr-pMsgHdr-signLen-2-4);
		EVP_DigestFinal_ex(&mdctx, myHash, &mdLen);
		for (i=0; i<16; i++) {
			printf("%x ", myHash[i]);
		}
		printf("\n");
	}
	/*
	 * TODO: (MD5 || SHA) hash comparison
	 */
	
	ssl->rawDataRead +=	(ptr - pMsgHdr);
	ssl->rawDataLen -= ssl->rawDataRead;

	FIN_DIGEST_UPDATE(ssl->rawDataBuf + SSLMTHdr, ptr-pMsgHdr);
	
	cc = nextStep; 
bail:
#if defined(DEBUG)
	fclose(logFile);
#endif
	if (pEphMod) {
		free(pEphMod);
	}
	if (pEphExp)
		free(pEphExp);
	return cc;
#undef USE_EPH_KEY
}

/*
 * Sends ClientKeyExchange packet which contains
 * the pre_master_secret for symmetric key computation.
 *
 * TODO: Assume we are using RSA key exchange algorithm, modify
 *       this constraint for more flexibility.
 */
static int s31ClnSendCKE(int nextStep)
{
	FILE *logFile = NULL;
#if defined(DEBUG)
	assert(CLNLOGDIR != NULL);
	char logName[strlen("clientKeyExchange") + strlen(CLNLOGDIR) + 1];
	sprintf(&logName[0], "%sclientKeyExchange", CLNLOGDIR);
	logFile = fopen(logName, "w+");
#endif
	int cc = -1;
	u1 *pCipher = NULL, *pRand = NULL, preMS[48]; 
	RSA *rsa = EVP_PKEY_get1_RSA(ssl->pubKey);

	/* generate pre_master_secret and encrypt it by server's public key */
	writeBE(preMS, SSL_VERSION, 2);
	pRand = genRandom(46);
	writeArrBE(preMS+2, pRand, 1, 46);
	pCipher = (u1 *) malloc(sizeof(u1) * RSA_size(rsa));

	if (RSA_public_encrypt(PRE_MASTER_SECRET_SIZE, preMS, pCipher, 
						   rsa, RSA_PKCS1_PADDING) != RSA_size(rsa)) 
	{
		printf("Encryption failed by server's public key\n");
		goto bail;
	}

	u1 *ptr, *pData; 

	pData = ptr = 
		ssl->rawDataBuf + SSLMsgBody; // point to data directly

	/* IMPORTANT: write cipher text length before the cipher */
	ptr += writeBE(ptr, RSA_size(rsa), 2); 	
	ptr += writeArrBE(ptr, pCipher, sizeof(pCipher[0]), RSA_size(rsa));
	
	writeBE(ssl->rawDataBuf + SSLMTLen, ptr-pData, 3);
	writeBE(ssl->rawDataBuf + SSLMTHdr, 
			SSL_MT_HSK_CLIENT_KEY_EXCHANGE, 1);

	if (sslSendPacket(ssl, SSL_RT_HANDSHAKE, SSL_VERSION, 
					  (ptr-pData)+SSLMTHdrLen, logFile) < 0) 
	{
		printf("ClientKeyExchange sent Failed\n");
		goto bail;
	}

	ssl->masterSecret = genMasterSecret(ssl, preMS, SSL_VERSION);
	ssl->keys = genKeyPairs(ssl, SSL_VERSION);

	FIN_DIGEST_UPDATE(ssl->rawDataBuf + SSLMTHdr,
					  (ptr-pData)+SSLMTHdrLen);
	
	cc = nextStep;
bail:
#if defined(DEBUG)
	fclose(logFile);
#endif
	if (pRand != NULL)
		free(pRand);
	if (pCipher != NULL)
		free(pCipher);
	return cc;
}

/*
 * This function sends ChangeCipherSpec and Finished message to server
 */
static int s31ClnSendFIN(int nextStep)
{
	FILE *logFile1 = NULL;
	FILE *logFile2 = NULL;
#if defined(DEBUG)
	assert(CLNLOGDIR != NULL);
	char logName1[strlen("clientChangeCipherSpec") + strlen(CLNLOGDIR) + 1];
	char logName2[strlen("clientFinish") + strlen(CLNLOGDIR) + 1];
	sprintf(&logName1[0], "%sclientChangeCipherSpec", CLNLOGDIR);
	sprintf(&logName2[0], "%sclientFinish", CLNLOGDIR);
	logFile1 = fopen(logName1, "w+");
	logFile2 = fopen(logName2, "w+");
#endif
	int cc = -1;

	u1 *ptr, *pData; 

	/* 
	 * Send ChangeCipherSpec
	 */
	writeBE(ssl->rawDataBuf + SSLMTHdr, SSL_MT_CCS, 1);

	if (sslSendPacket(ssl, SSL_RT_CHANGE_CIPHER_SPEC, SSL_VERSION, 
					  1, logFile1) < 0)
	{
		printf("Client finished sent Failed\n");
		goto bail;
	}

	/* 
	 * Send Finished
	 */
	int plainLen = 4 + TLS_VERIFY_DATA_SIZE;

	pData = ptr = 
		ssl->rawDataBuf + SSLRTHdrLen; // point to data directly

	ptr += writeBE(ptr, SSL_MT_HSK_FINISHED, 1);
	ptr += writeBE(ptr, TLS_VERIFY_DATA_SIZE, 3);
	
	genFinMsg(ssl, (u1 *)TLS_CLIENT_FINISH_CONST, 
			  TLS_CLIENT_FINISH_CONST_SIZE, ptr, 
			  TLS_VERIFY_DATA_SIZE, SSL_VERSION);

	FIN_DIGEST_UPDATE(pData, TLS_VERIFY_DATA_SIZE + 4);

	/* client initialize cipher context for encryption */
	EVP_EncryptInit_ex(ssl->cipherWCtx, 
					   (const EVP_CIPHER *)ssl->cs->cipher, NULL,
					   ssl->keys->clientW, ssl->keys->clientIV);
	EVP_CIPHER_CTX_set_padding(ssl->cipherWCtx, false);
	
	int cipherLen;

	/* encrypt plain text in pData, then write result to pData */
	cipherLen = 
		sslSessionEnc(ssl, pData, plainLen, pData, 
					  SSL_RT_HANDSHAKE, SSL_VERSION, SSL_CLIENT);

	if (sslSendPacket(ssl, SSL_RT_HANDSHAKE, SSL_VERSION, 
					  cipherLen, logFile2) < 0) 
	{
		printf("ClientKeyExchange sent Failed\n");
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
 * This function receives ChangeCipherSpec and Finished message 
 * from server
 */
static int s31ClnRecvFIN(int nextStep)
{
	FILE *logFile1 = NULL;
	FILE *logFile2 = NULL;
#if defined(DEBUG)
	assert(CLNLOGDIR != NULL);
	char logName1[strlen("serverChangeCipherSpec") + strlen(CLNLOGDIR) + 1];
	char logName2[strlen("serverFinish") + strlen(CLNLOGDIR) + 1];
	sprintf(&logName1[0], "%sserverChangeCipherSpec", CLNLOGDIR);
	sprintf(&logName2[0], "%sserverFinish", CLNLOGDIR);
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
	u1 *pData = NULL, *ptr = NULL;
	int mtHdr, msgLen;
	/* 
	 * Receive ChangeCipherSpec
	 */
	pData = ptr = ssl->rawDataBuf + SSLMTHdr;

	ptr += readBE(ptr, &mtHdr, 1);
	CHECK_HDR(SSL_MT_CCS, mtHdr, R, bail);
	
	ssl->rawDataRead +=	(ptr - pData);
	ssl->rawDataLen -= ssl->rawDataRead;

	/* Receive Finished */
	if (ssl->rawDataLen == 0) {
		if (sslRecvPacket(ssl, SSL_RT_HANDSHAKE, SSL_VERSION, 
						  logFile2) < 0)
			goto bail;
	}
	/* points to encrypted cipher text */
	pData = ptr = ssl->rawDataBuf + SSLMTHdr;
	
	u1 data[TLS_VERIFY_DATA_SIZE];
	int plainLen = 0;
	
	/* decryption */
	EVP_DecryptInit_ex(ssl->cipherRCtx, 
					   (const EVP_CIPHER *)ssl->cs->cipher, NULL,
					   ssl->keys->serverW, ssl->keys->serverIV);
	EVP_CIPHER_CTX_set_padding(ssl->cipherRCtx, false);
	
	plainLen = 
		sslSessionDec(ssl, ptr, ssl->rawDataLen, ptr, 
					  SSL_RT_HANDSHAKE, SSL_VERSION, SSL_CLIENT);

	if (plainLen < 0) {
		printf("decryption failed\n");
		goto bail;
	}
	ptr += readBE(ptr, &mtHdr, 1);
	CHECK_HDR(SSL_MT_HSK_FINISHED, mtHdr, M, bail);
	
	ptr += readBE(ptr, &msgLen, 3);
	if (msgLen != TLS_VERIFY_DATA_SIZE) {
		printf("Inconsistent message length:client:%x, server:%x\n",
			   TLS_VERIFY_DATA_SIZE, msgLen);
	}
	
	genFinMsg(ssl, (u1 *)TLS_SERVER_FINISH_CONST, 
			  TLS_SERVER_FINISH_CONST_SIZE, data, 
			  TLS_VERIFY_DATA_SIZE, SSL_VERSION);
	
	/* handshake message verification */
	if (plainLen == 0 || 
		memcmp(data, ptr, TLS_VERIFY_DATA_SIZE) != 0) 
	{
		printf("handshake message verification failed\n");
		goto bail;
	}
	ptr += plainLen;
	
	ssl->rawDataRead +=	(ptr - pData);
	ssl->rawDataLen -= ssl->rawDataRead;

	cc = nextStep;
bail:
#if defined(DEBUG)
	fclose(logFile1);
	fclose(logFile2);
#endif
	return cc;
}
/*
 * Client do handshake with server
 */
int s31ClnHSK()
{
	/*
	 * step description:
	 * 
	 * step >=  0  -> switch to next step number and execute
	 * step == -1  -> abnormal finish
	 * step == SSL_MT_HSK_SUCCESS -> handshake success
	 */
	int step = 1, nextStep;
	int finSR;
	bool sessionResumed = false;

	while (step >= 0 && step != SSL_MT_HSK_SUCCESS) {
		switch(step) {
			case SSL_MT_HSK_HELLO_REQUEST:
				break;
			case SSL_MT_HSK_CLIENT_HELLO: /* Send ClientHello */
				nextStep = SSL_MT_HSK_SERVER_HELLO;
				step = s31ClnSendCH(nextStep);
				break;
			case SSL_MT_HSK_SERVER_HELLO: /* Receive ServerHello */
				nextStep = SSL_MT_HSK_CERTIFICATE;
				step = s31ClnRecvSH(nextStep);
				break;
			case SSL_MT_HSK_CERTIFICATE: /* Client Verify server's certificate */
				if (ssl->cs->isExport)
					nextStep = SSL_MT_HSK_SERVER_KEY_EXCHANGE;
				else 
					nextStep = SSL_MT_HSK_SERVER_DONE;

				step = s31ClnVerifyCert(nextStep);
				break;
			case SSL_MT_HSK_SERVER_KEY_EXCHANGE:
				nextStep = SSL_MT_HSK_SERVER_DONE;
				step = s31ClnRecvSKE(nextStep);
				break;
			case SSL_MT_HSK_CERTIFICATE_REQUEST:
				break;
			case SSL_MT_HSK_SERVER_DONE: /* Receive ServerHelloDone */
				nextStep = SSL_MT_HSK_CLIENT_KEY_EXCHANGE;
				step = s31ClnRecvSHD(nextStep);
				break;
			case SSL_MT_HSK_CERTIFICATE_VERIFY:
				break;
			case SSL_MT_HSK_CLIENT_KEY_EXCHANGE: /* Send ClientKeyExchange */
				nextStep = SSL_MT_HSK_FINISHED;
				step = s31ClnSendCKE(nextStep);
				finSR = 1;
				break;
			case SSL_MT_HSK_FINISHED:
				if (finSR == 1) {		// send
					if (sessionResumed) {
						nextStep = SSL_MT_HSK_SUCCESS;
					} else {
						finSR = 2;
					}
					step = s31ClnSendFIN(nextStep);
				} else if (finSR == 2){	// receive
					if (sessionResumed) {
						finSR = 1;
					} else {
						nextStep = SSL_MT_HSK_SUCCESS;
					}
					step = s31ClnRecvFIN(nextStep);
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

SSL_METH clnMeth = {
	s31ClnHSK,
	s31Version,
};

SSL_METH* s31ClnMeth()
{
	return &clnMeth; 
}

void s31ClnEnt(void *cmdTable)
{
	extern int errno;
	struct sockaddr_in saddr;
	int sockfd;
	CmdTable *cmds = (CmdTable *)cmdTable;

	if (cmds->ipAddr == NULL) {
		printf("Connection IP address required\n");
		goto bail;
	}
	if (cmds->port == 0) {
		printf("Connection port required\n");
		goto bail;
	}
	
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("opening socket error\n");
		goto bail;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(cmds->port);
	if (inet_pton(AF_INET, cmds->ipAddr, &saddr.sin_addr) <= 0) {
		printf("inet_pton error\n");
		goto bail;
	}

	if (connect(sockfd, (struct sockaddr *) &saddr, 
				sizeof(saddr)) < 0) 
	{
		printf("cannot connect to server\n");
		goto bail;
	}
	ssl = sslInit(sockfd, cmds, SSL_CLIENT);

	if (s31ClnHSK() == SSL_MT_HSK_SUCCESS) {
		printf("HANDSHAKE SUCCESS\n");

		FILE *inLog = NULL;
		FILE *outLog = NULL;
#if defined(DEBUG)
		assert(CLNLOGDIR != NULL);
		char logName1[strlen("clientIn") + strlen(CLNLOGDIR) + 1];
		char logName2[strlen("clientOut") + strlen(CLNLOGDIR) + 1];
		sprintf(&logName1[0], "%sclientIn", CLNLOGDIR);
		sprintf(&logName2[0], "%sclientOut", CLNLOGDIR);
		inLog = fopen(logName1, "w+");
		outLog = fopen(logName2, "w+");
#endif
		sslStdIOApp(ssl, SSL_VERSION, SSL_CLIENT,
					inLog, outLog);

#if defined(DEBUG)
	fclose(inLog);
	fclose(outLog);
#endif
	} else {
		printf("HANDSHAKE FAILED\n");
	}

bail:
	sslClean(ssl, sockfd, SSL_CLIENT);
	printf("CLIENT EXIT\n");
}

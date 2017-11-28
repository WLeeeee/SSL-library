#include <string.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <openssl/engine.h>

#include "../Common.h"
#include "../utils/FileIO.h"
#include "SSLLib.h"

CipherSuite cipherTable[] = {
	{"TLS_RSA_WITH_NULL_MD5", 0x01, 
		&EVP_enc_null, NULL, 
		&EVP_md5, NULL, 0, false},
	{"TLS_RSA_WITH_NULL_SHA", 0x02, 
		&EVP_enc_null, NULL, 
		&EVP_sha, NULL, 0, false},
	{"TLS_RSA_EXPORT_WITH_RC4_40_MD5", 0x03, 
		&EVP_rc4, NULL, 
		&EVP_md5, NULL, 5, true},
	{"TLS_RSA_WITH_RC4_128_MD5", 0x04, 
		&EVP_rc4, NULL, 
		&EVP_md5, NULL, 16, false},
	{"TLS_RSA_WITH_RC4_128_SHA", 0x05, 
		&EVP_rc4, NULL, 
		&EVP_sha1, NULL, 16, false},
	{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0xA,
		&EVP_des_ede3_cbc, NULL,
		&EVP_sha1, NULL, 21, false},
	{"TLS_RSA_WITH_AES_128_CBC_SHA", 0x2F,
		&EVP_aes_128_cbc, NULL,
		&EVP_sha1, NULL, 16, false},
	{"TLS_RSA_WITH_AES_256_CBC_SHA", 0x35,
		&EVP_aes_256_cbc, NULL,
		&EVP_sha1, NULL, 32, false},
	{"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", 0x41,
		&EVP_camellia_128_cbc, NULL,
		&EVP_sha1, NULL, 16, false},
	{"NULL", 0x00, NULL, NULL, 0, false},
};

/*
 * Auxiliary function which is used by pseudo random function
 * for generating an arbitrary length byte string and trimming 
 * its length to specified outLen. Then the result will be put 
 * in out. This function uses the HMAC_hash function to generate
 * random string.
 */
static void runPHash(const EVP_MD *hash, u1 *secret, int secretLen,
					 u1 *seed, int seedLen, u1 *out, int outLen)
{
	u4 hashSize = EVP_MD_size(hash);
	/* total message for HMAC_hash computation */
	u1 *pMAC = (u1 *) malloc(sizeof(u1) * (hashSize + seedLen));

	/* initialize */
	HMAC(hash, secret, secretLen, seed, seedLen, pMAC, &hashSize);
	
	int curLen = 0;
	while (true) {
		memcpy(pMAC+hashSize, seed, seedLen);
		if (curLen+hashSize > outLen) {
			u1 tmp[EVP_MAX_MD_SIZE];
			HMAC(hash, secret, secretLen, pMAC, hashSize+seedLen, 
				 tmp, &hashSize);
			memcpy(out+curLen, tmp, outLen-curLen);
			break;
		}
		HMAC(hash, secret, secretLen, pMAC, hashSize+seedLen, 
			 out+curLen, &hashSize);
		HMAC(hash, secret, secretLen, pMAC, hashSize, pMAC, &hashSize);
		curLen += hashSize;
	}
	
	if (pMAC)
		free(pMAC);
}

/*
 * SSL Pseudo Random Function
 *
 * In SSL protocol, the two hash functions used by PRF
 * is MD5 and SHA-1. After running PRF, the result will
 * be written to out with specified output length.
 */
static void runPRF(const EVP_MD *md5, const EVP_MD *sha1, 
				   u1 *secret, int secretLen, 
				   u1 *label, int labelLen, 
				   u1 *seed, int seedLen, u1 *out, int outLen)
{
	int halfLen = (secretLen + (secretLen & 0x1)) >> 1;
	u1 *s1;
	/* modify s2 if secret length is odd */
	u1 *s2;
	u1 *pPHashSeed = (u1 *) malloc(sizeof(u1) * (labelLen + seedLen));
	
	if (secretLen == 0) {
		s1 = s2 = NULL;
	} else {
		s1 = secret;
		s2 = secret + halfLen - (secretLen & 0x1);
	}

	memcpy(pPHashSeed, label, labelLen);
	memcpy(pPHashSeed+labelLen, seed, seedLen);
	
	u1 *md5Out = (u1 *) malloc(sizeof(u1) * outLen);
	u1 *sha1Out = (u1 *) malloc(sizeof(u1) * outLen);

	runPHash(md5, s1, halfLen, 
			 pPHashSeed, (labelLen + seedLen), md5Out, outLen);
	runPHash(sha1, s2, halfLen, 
			 pPHashSeed, (labelLen + seedLen), sha1Out, outLen);

	int i;
	for (i=0; i<outLen; i++) {
		out[i] = md5Out[i] ^ sha1Out[i];
	}
	if (pPHashSeed)
		free(pPHashSeed);
	if (md5Out)
		free(md5Out);
	if (sha1Out)
		free(sha1Out);
}

/*
 * This function is used only when the cipher suite is exportable.
 * 
 * Inconsistent of openssl and TLS protocol spec:
 * The key length of EXPORT_RC4_40 in spec is 5 bytes, however 
 * the key length in openssl is 16 bytes. Thus, we must use 5-bytes
 * key material for generating the final write keys if the algorithm
 * is EXPORT_RC4_40.
 */
static void genExpFinKeys(SSLSession *ssl, KeyPairs *pKeys, 
						  int version)
{
	u1 seed[CLIENT_RANDOM_SIZE + SERVER_RANDOM_SIZE];

	memcpy(seed, ssl->clnRandom, CLIENT_RANDOM_SIZE);
	memcpy(seed + CLIENT_RANDOM_SIZE, ssl->svrRandom, 
			SERVER_RANDOM_SIZE);
	
	if (version >= SSL31_VERSION) {
		/* SSL version >= TLS1, use PRF to generate */
	
		/* final client write key */
		runPRF(EVP_md5(), EVP_sha1(), pKeys->clientW, 
			   ssl->cs->keyMaterial,
			   (u1 *)TLS_CLIENT_WRITE_KEY_CONST, 
			   TLS_CLIENT_WRITE_KEY_CONST_SIZE, seed, 
			   SERVER_RANDOM_SIZE+CLIENT_RANDOM_SIZE, 
			   pKeys->clientW,
			   EVP_CIPHER_key_length(ssl->cs->cipher));
	
		/* final server write key */
		runPRF(EVP_md5(), EVP_sha1(), pKeys->serverW, 
			   ssl->cs->keyMaterial,
			   (u1 *)TLS_SERVER_WRITE_KEY_CONST, 
			   TLS_SERVER_WRITE_KEY_CONST_SIZE, seed, 
			   SERVER_RANDOM_SIZE+CLIENT_RANDOM_SIZE, 
			   pKeys->serverW,
			   EVP_CIPHER_key_length(ssl->cs->cipher));
		/* CBC */
		if (EVP_CIPHER_iv_length(ssl->cs->cipher) != 0) {
			/* client IV */
			runPRF(EVP_md5(), EVP_sha1(), NULL, 0, 
					(u1 *)TLS_IV_BLOCK_CONST,
					TLS_IV_BLOCK_CONST_SIZE, seed, 
					SERVER_RANDOM_SIZE+CLIENT_RANDOM_SIZE, 
					pKeys->clientIV, 
					EVP_CIPHER_iv_length(ssl->cs->cipher));
			/* server IV */
			memcpy(pKeys->serverIV, pKeys->clientIV,
				   EVP_CIPHER_iv_length(ssl->cs->cipher));
		}
	} else {
		/* SSL version <= SSL3.0, use normal way to generate */
	}
}
/*
 * This function generates the HMAC.
 * The seed of HMAC is:
 * seed = sequence number(8 bytes) || record layer type(1 byte) ||
 *		  ssl version(2 bytes) || data(dataLen bytes)
 *
 * For data, it does not contain the record layer header. 
 *
 * For dataLen, if data comes with data header, 
 * dataLen = header size + length of data.
 */
int genHMAC(EVP_MD *hash, u1 *macW, int macWLen, 
			u8 seq, u1 type, u2 version, 
			u1 *data, u2 dataLen, u1 *out)
{
	u4 hashSize;
	int seedLen = sizeof(seq) + sizeof(type) + sizeof(version) + 
				  sizeof(dataLen) + (dataLen * sizeof(u1));
	u1 *seed = (u1 *) malloc(sizeof(u1) * seedLen);
	u1 *ptr = seed;

	if (version == SSL31_VERSION) {
		/* SSL version >= TLS1, use PRF to generate */
		ptr += writeBE(ptr, seq, sizeof(seq));
		ptr += writeBE(ptr, type, sizeof(type));
		ptr += writeBE(ptr, version, sizeof(version));
		ptr += writeBE(ptr, dataLen, sizeof(dataLen));
		ptr += writeArrBE(ptr, data, 1, dataLen);

		HMAC(hash, macW, macWLen, seed, seedLen, out, &hashSize);
	} else {
	}
	
	if (seed)
		free(seed);

	return hashSize;
}

/*
 * Generate a digest of all previous handshake messages
 * for verification. Original context can't be finalize
 * because this function will occur twice.
 */
void genFinMsg(SSLSession *ssl, u1 *label, int labelLen, 
			   u1 *out, int outLen, int version)
{
	u4 mdLen;
	EVP_MD_CTX ctxFin;
	u1 digestHSK[MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH];
	u1 *ptr;

	ptr = digestHSK;
	EVP_MD_CTX_init(&ctxFin);

	/* finalize md5 */
	EVP_MD_CTX_copy_ex(&ctxFin, ssl->md5Fin);
	EVP_DigestFinal_ex(&ctxFin, ptr, &mdLen);

	/* finalize sha1 */
	ptr += mdLen; 
	EVP_MD_CTX_copy_ex(&ctxFin, ssl->sha1Fin);
	EVP_DigestFinal_ex(&ctxFin, ptr, &mdLen);
	
	runPRF(EVP_md5(), EVP_sha1(), ssl->masterSecret, 
		   MASTER_SECRET_SIZE, label, labelLen, digestHSK, 
		   MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH, out, outLen);
	EVP_MD_CTX_cleanup(&ctxFin);
}

/* 
 * Generate master_secret from pre_master_secret 
 * and return it.
 */
u1 *genMasterSecret(SSLSession *ssl, u1 *preMS, int version)
{
	u1 *ms;
	if (version >= SSL31_VERSION) {
		/* SSL version >= TLS1, use PRF to generate */
		u1 seed[SERVER_RANDOM_SIZE + CLIENT_RANDOM_SIZE];
		
		ms = (u1 *) malloc(sizeof(u1) * MASTER_SECRET_SIZE);
		memcpy(seed, ssl->clnRandom, CLIENT_RANDOM_SIZE);
		memcpy(seed + CLIENT_RANDOM_SIZE, ssl->svrRandom, 
			   SERVER_RANDOM_SIZE);

		runPRF(EVP_md5(), EVP_sha1(), preMS, PRE_MASTER_SECRET_SIZE, 
			   (u1 *)TLS_MASTER_SECRET_CONST, 
			   TLS_MASTER_SECRET_CONST_SIZE, seed, 
			   SERVER_RANDOM_SIZE+CLIENT_RANDOM_SIZE, 
			   ms, MASTER_SECRET_SIZE);

	} else {
		/* SSL version <= SSL3.0, use normal way to generate */
	}

	return ms;
}


/*
 * This function generates all required key pairs which will be 
 * used in session encryption/decryption.
 *
 * The required key pairs are:
 * client_write_MAC_secret
 * server_write_MAC_secret
 * client_write_key
 * server_write_key
 * client_write_iv
 * server_write_iv
 */
KeyPairs *genKeyPairs(SSLSession *ssl, int version)
{
	u1 *keyBlock;
	int keyBlockSize;
	KeyPairs *pKeys;
	u1 seed[SERVER_RANDOM_SIZE + CLIENT_RANDOM_SIZE];

	memcpy(seed, ssl->svrRandom, SERVER_RANDOM_SIZE);
	memcpy(seed + SERVER_RANDOM_SIZE, ssl->clnRandom, 
			CLIENT_RANDOM_SIZE);
	
	keyBlockSize = (EVP_CIPHER_key_length(ssl->cs->cipher) + 
				   EVP_CIPHER_iv_length(ssl->cs->cipher) +
				   EVP_MD_size(ssl->cs->digest)) << 1;
	keyBlock = (u1 *) malloc(sizeof(u1) * keyBlockSize);
	
	pKeys = (KeyPairs *) malloc(sizeof(KeyPairs));

	if (version >= SSL31_VERSION) {
		/* SSL version >= TLS1, use PRF to generate */
		runPRF(EVP_md5(), EVP_sha1(), ssl->masterSecret, 
			   MASTER_SECRET_SIZE, 
			   (u1 *)TLS_KEY_EXPANSION_CONST, 
			   TLS_KEY_EXPANSION_CONST_SIZE, seed, 
			   SERVER_RANDOM_SIZE+CLIENT_RANDOM_SIZE, 
			   keyBlock, keyBlockSize);
	} else {
		/* SSL version <= SSL3.0, use normal way to generate */
	}

	/* assign keys */
	pKeys->data = keyBlock;
	pKeys->clientMAC = keyBlock;
	keyBlock += EVP_MD_size(ssl->cs->digest);
	pKeys->serverMAC = keyBlock;

	keyBlock += EVP_MD_size(ssl->cs->digest);
	pKeys->clientW = keyBlock; 

	keyBlock += EVP_CIPHER_key_length(ssl->cs->cipher);
	pKeys->serverW = keyBlock;

	/* CBC */
	if (EVP_CIPHER_iv_length(ssl->cs->cipher) != 0) {
		keyBlock += EVP_CIPHER_key_length(ssl->cs->cipher);
		pKeys->clientIV = keyBlock;
		keyBlock += EVP_CIPHER_iv_length(ssl->cs->cipher);
		pKeys->serverIV = keyBlock;
	} else 
		pKeys->clientIV = pKeys->serverIV = NULL; 

	/* get final key pairs if algorithm is exportable */
	if (ssl->cs->isExport) {
		/* 
		 * If Server write key material and final client write key 
		 * are overlap, we must move server key material to
		 * the address of final server write key before computng 
		 * final write key.
		 */
		if (ssl->cs->keyMaterial < 
			EVP_CIPHER_key_length(ssl->cs->cipher)) 
		{
			u1 serverW[ssl->cs->keyMaterial];
			memcpy(serverW, 
				   pKeys->clientW+ssl->cs->keyMaterial, 
				   ssl->cs->keyMaterial);
			memcpy(pKeys->serverW, serverW, 
				   ssl->cs->keyMaterial);
		}
		genExpFinKeys(ssl, pKeys, version);
	}
#ifndef NOOUTPUT
	int i;
	printf("client Mac\n");
	for (i=0; i<20; i++) {
		printf("%x ", pKeys->clientMAC[i]);
	}
	printf("\nserver Mac\n");
	for (i=0; i<20; i++) {
		printf("%x ", pKeys->serverMAC[i]);
	}
	printf("\nclient key\n");
	for (i=0; i<16; i++) {
		printf("%x ", pKeys->clientW[i]);
	}
	printf("\nserver key\n");
	for (i=0; i<16; i++) {
		printf("%x ", pKeys->serverW[i]);
	}
	printf("\nclient IV\n");
	for (i=0; i<EVP_CIPHER_iv_length(ssl->cs->cipher); i++) {
		printf("%x ", pKeys->clientIV[i]);
	}
	printf("\nserver IV\n");
	for (i=0; i<EVP_CIPHER_iv_length(ssl->cs->cipher); i++) {
		printf("%x ", pKeys->serverIV[i]);
	}
	printf("\n");
#endif
	return pKeys;
}

/*
 * This function will find and return the corresponding cipher suite
 * by the cipher ID. If match, the matched cipher suite will be 
 * returned, else, NULL will be returned.
 */
CipherSuite *getCipherByID(u4 cipherID)
{
	int i = 0;
	while (cipherTable[i].ID != 0x0) {
		if (cipherTable[i].ID == cipherID) {
			return &cipherTable[i];
		}
		i++;
	}
	return NULL;
}

/*
 * Real function which is used to read ssl packet from socket 
 * and write to message buffer for further processing. On success, 
 * number of received bytes will be returned, else -1 will be 
 * returned.
 */
int sslRecvPacket(SSLSession *ssl, int sslRT, int sslVer, 
				  FILE *logFile)
{
	int cc = -1;
	int pktHdr, pktVer;
	int readLen;
	
	/* Read packet header and check */
	readLen = readFD(ssl->connfd, ssl->rawDataBuf, 
					 SSLRTHdrLen, logFile);

	if (readLen <= 0) {
		printf("SOCKET CLOSED\n");
		goto bail;
	}

	readBE(ssl->rawDataBuf + SSLRTHdr, &pktHdr, 1);
	CHECK_HDR(sslRT, pktHdr, R, bail);

	readBE(ssl->rawDataBuf + SSLRTVer, &pktVer, 2);
	CHECK_VER(sslVer, pktVer, R, bail);
	
	readBE(ssl->rawDataBuf + SSLRTLen, &(ssl->rawDataLen), 2);

	/* Receive all messages from socket */
	readLen = 
		readFD(ssl->connfd, ssl->rawDataBuf+SSLRTHdrLen, 
			   ssl->rawDataLen, logFile);

	if (readLen <= 0) {
		printf("SOCKET CLOSED\n");
		goto bail;
	}
	
	CHECK_READ(ssl->rawDataLen, readLen, bail);

	/* 
	 * All raw data is ready for reading and processing. Thus,
	 * this field will be reset to zero because no data has been
	 * processed yet in the rawDataBuf.
	 */
	ssl->rawDataRead = 0;

	cc = 1;	// success
bail:
	return cc;
}
/*
 * Real function which is used to write ssl packet header and 
 * send it to socket. sslRT represents the message type we want to 
 * send. sslMTLen is the full message size (i.e. message type header 
 * is included). On success, packet sent length will be returned, 
 * else -1 will be returned.
 */
int sslSendPacket(SSLSession *ssl, int sslRT, int sslVer, 
				  int sslMTLen, FILE *logFile)
{
	u1 *ptr = ssl->rawDataBuf;
	int cc = -1;

	ptr += writeBE(ptr, sslRT, 1);
	ptr += writeBE(ptr, sslVer, 2);
	ptr += writeBE(ptr, sslMTLen, 2);

	/* Send packet to socket */
	cc = writeFD(ssl->connfd, ssl->rawDataBuf, 
				 sslMTLen + SSLRTHdrLen, logFile);
	return cc;
}

/*
 * This function read and check the message type header and return 
 * the address of the message body. The msgLen argument will be 
 * filled with the length of the message body. Finally, the whole
 * message will be digested for generating the verify data in finished
 * message.
 */
u1* sslReadMTHdr(SSLSession *ssl, int *msgLen, int sslMT, int sslVer)
{
	int msgType;
	int totalLen;
	u1 *pHdr, *ptr;
	int cc = -1;

	/* point to message header */
	pHdr = ptr = 
		ssl->rawDataBuf + SSLRTHdrLen + ssl->rawDataRead;

	ptr += readBE(ptr, &msgType, 1);
	CHECK_HDR(sslMT, msgType, M, bail);

	if (msgLen == NULL) { //only used by ChangeCipherSpec
		totalLen = 1;
		goto ccs_bail;
	}

	ptr += readBE(ptr, msgLen, 3);

	totalLen = *msgLen + SSLMTHdrLen;

	FIN_DIGEST_UPDATE(pHdr, totalLen);

ccs_bail:

	cc = 1;
bail:
	if (cc == -1)
		return NULL;
	
	ssl->rawDataRead += totalLen;
	ssl->rawDataLen -= totalLen;
	
	return ptr;
}

/*
 * This function fill the message header with type and length. The
 * whole message length (i.e. message header and message body) will 
 * be returned. Finally, the whole message will be digested for 
 * generating the verify data in finished message.
 */
int sslWriteMTHdr(SSLSession *ssl, int msgLen, int sslMT, int sslVer)
{
	writeBE(ssl->rawDataBuf + SSLMTLen, msgLen, 3);
	writeBE(ssl->rawDataBuf + SSLMTHdr, sslMT, 1);

	int totalLen = msgLen + SSLMTHdrLen;

	FIN_DIGEST_UPDATE((ssl->rawDataBuf + SSLMTHdr), totalLen);

	return totalLen;
}
/* 
 * Generate a stream of random numbers with number 
 * of bytes and return the generated stream.
 */
u1 *genRandom(int byte)
{
	u1 *random = (u1 *) malloc(sizeof(u1) * byte);
	int i;

	srand(time(NULL));
	
	for (i=0; i<byte; i++) {
		random[i] = rand() % 256;
	}

	return random;
}
/*
 * On success, the padding number will be returned and padding
 * will be written to plainTail.
 */
int sslCBCPadding(SSLSession *ssl, u1 *plainTail, int plainLen)
{
	int targetLen = 
		(plainLen + EVP_CIPHER_block_size(ssl->cs->cipher)) - 
		(plainLen % EVP_CIPHER_block_size(ssl->cs->cipher));
	int paddingLen = targetLen - plainLen;
	int i;

	for (i=0; i<paddingLen; i++) {
		plainTail[i] = (paddingLen-1);
	}

	return paddingLen;
}

/*
 * This function combines HMAC generation and message encryption for
 * the plainText before sending to receiver. Thus, it can be used only 
 * after session encryption key is computed. On success, length of 
 * cipherText will be returned and the encrypted data will be put in 
 * cipherText, else 0 will be returned.
 *
 * Warning:
 * plainText must have enough space for (plainText || HMAC) and 
 * cipherText must have enough space for padded cipherText, else
 * buffer overflow may occur.
 */
int sslSessionEnc(SSLSession *ssl, u1 *plainText, int plainLen,
				  u1 *cipherText, int sslRT, int sslVer, int which)
{
	int mdLen = EVP_MD_size(ssl->cs->digest);
	int cipherLen;
	int seq;
	u1 *pMAC;
	
	if (which == SSL_CLIENT) {
		pMAC = ssl->keys->clientMAC;
		seq = ssl->clnSeq++;
	}
	else {
		pMAC = ssl->keys->serverMAC;
		seq = ssl->svrSeq++;
	}

	genHMAC(ssl->cs->digest, pMAC, 
			mdLen, seq, sslRT, sslVer, 
			plainText, plainLen, plainText+plainLen);
	
	plainLen += mdLen;

	/* padding for CBC */
	if (EVP_CIPHER_iv_length(ssl->cs->cipher) != 0) {
		plainLen += sslCBCPadding(ssl, plainText+plainLen, plainLen);
/*		int i;
		printf("encryption??");
		for (i=0; i<plainLen; i++) {
			printf("%x ", plainText[i]);
		}
		printf("\n");*/
	}

	EVP_EncryptUpdate(ssl->cipherWCtx, cipherText, &cipherLen, 
					  plainText, plainLen);
	return cipherLen;
}

/*
 * This function combines HMAC generation and message decryption for
 * the cipherText. Thus, it can be used only after session encryption 
 * key is computed. On success, length of plainText will be returned 
 * and the decrypted data will be put in plainText, else 0 will be 
 * returned.
 * 
 * Warning:
 * plainText must have enough space for (plainText || HMAC), else
 * buffer overflow may occur.
 */
int sslSessionDec(SSLSession *ssl, u1 *cipherText, int cipherLen, 
				  u1 *plainText, int sslRT, int sslVer, int which)
{
	int plainLen;
	int mdLen = EVP_MD_size(ssl->cs->digest);
	int seq;
	u1 hmac[EVP_MAX_MD_SIZE];
	u1 *pMAC;

	if (which == SSL_CLIENT) {
		pMAC = ssl->keys->serverMAC;
		seq = ssl->svrSeq++;
	}
	else {
		pMAC = ssl->keys->clientMAC;
		seq = ssl->clnSeq++;
	}
	if (!EVP_DecryptUpdate(ssl->cipherRCtx, plainText, &plainLen, 
						   cipherText, cipherLen))
	{
		printf("decryption failed\n");
		goto bail;
	}

	/*
	 * trimming & checking padding
	 */
	if (EVP_CIPHER_iv_length(ssl->cs->cipher) != 0) {
		int padLen = plainText[plainLen-1];
		
		int i;
		for (i=(plainLen-(padLen+1)); i<padLen; i++) {
			if (plainText[i] != padLen) {
				printf("Bad padding length\n");
				goto bail;
			}
		}
		plainLen -= (padLen+1);
	}

	genHMAC(ssl->cs->digest, pMAC, 
			mdLen, seq, sslRT, sslVer, 
			plainText, plainLen-mdLen, hmac);

	/* HMAC verification */
	if (memcmp(&plainText[plainLen-mdLen], hmac, mdLen) != 0) 
	{
		printf("MAC verification failed\n");
		goto bail;
	}
	
	return plainLen;

bail:
	return -1;
}

/*
 * Initialize the ssl table
 */
SSLSession* sslInit(int connfd, CmdTable *cmds, int which)
{
	SSLSession *ssl = NULL;

	ssl = (SSLSession *) malloc(sizeof(SSLSession));
	memset(ssl, 0, sizeof(SSLSession));

	if (which == SSL_SERVER) {
		/* setup x509 certificate */
		FILE *certFile = fopen(cmds->certPath, "r");
		if (!certFile || !cmds->certPath) {
			printf("Cannot open PEM file:%s\n", 
					cmds->certPath);
			fclose(certFile);
			goto bail;
		}
		PEM_read_PrivateKey(certFile, &(ssl->priKey), NULL, NULL);
		if (ssl->priKey == NULL) {
			printf("Cannot parse private key from PEM file:%s\n", 
					cmds->certPath);
			fclose(certFile);
			goto bail;
		}
		PEM_read_X509(certFile, &(ssl->certX509), NULL, NULL);
		if (ssl->certX509 == NULL) {
			printf("Cannot parse x509 certificate from PEM file:%s\n", 
					cmds->certPath);
			fclose(certFile);
			goto bail;
		}
		fclose(certFile);
	}
	
	ssl->connfd = connfd;
	ssl->rawDataBuf = (u1 *) malloc(sizeof(u1) * MSG_LIMIT);

	/* initialize finish message hash */
	ssl->md5Fin = (EVP_MD_CTX *) malloc(sizeof(EVP_MD_CTX));
	memset(ssl->md5Fin, 0, sizeof(EVP_MD_CTX));
	ssl->sha1Fin = (EVP_MD_CTX *) malloc(sizeof(EVP_MD_CTX));
	memset(ssl->sha1Fin, 0, sizeof(EVP_MD_CTX));
	
	ssl->cipherRCtx = 
		(EVP_CIPHER_CTX *) malloc(sizeof(EVP_CIPHER_CTX));
	memset(ssl->cipherRCtx, 0, sizeof(EVP_CIPHER_CTX));
	ssl->cipherWCtx = 
		(EVP_CIPHER_CTX *) malloc(sizeof(EVP_CIPHER_CTX));
	memset(ssl->cipherRCtx, 0, sizeof(EVP_CIPHER_CTX));
	
	if (!EVP_DigestInit_ex(ssl->md5Fin, EVP_md5(), NULL)) 
		goto bail;
	if (!EVP_DigestInit_ex(ssl->sha1Fin, EVP_sha1(), NULL)) 
		goto bail;

	EVP_CIPHER_CTX_init(ssl->cipherRCtx);
	EVP_CIPHER_CTX_init(ssl->cipherWCtx);

	return ssl;
bail:
	if (ssl) {
		if (ssl->rawDataBuf)
			free(ssl->rawDataBuf);
		if (ssl->md5Fin) {
			EVP_MD_CTX_cleanup(ssl->md5Fin);
			free(ssl->md5Fin);
		}
		if (ssl->sha1Fin) {
			EVP_MD_CTX_cleanup(ssl->sha1Fin);
			free(ssl->sha1Fin);
		}
		if (ssl->cipherRCtx) {
			EVP_CIPHER_CTX_cleanup(ssl->cipherRCtx);
			free(ssl->cipherRCtx);
		}
		if (ssl->cipherWCtx) {
			EVP_CIPHER_CTX_cleanup(ssl->cipherWCtx);
			free(ssl->cipherWCtx);
		}
		if (ssl->priKey)
			EVP_PKEY_free(ssl->priKey);
		if (ssl->pubKey)
			EVP_PKEY_free(ssl->pubKey);
		if (ssl->certX509) 
			X509_free(ssl->certX509);

		free(ssl);
	}
	return NULL;
}

/*
 * Cleanup the ssl table
 */
void sslClean(SSLSession *ssl, int connfd, int which)
{
	if (ssl == NULL)
		return;

	if (ssl->clnRandom)
		free(ssl->clnRandom);
	if (ssl->svrRandom)
		free(ssl->svrRandom);
	if (ssl->sID)
		free(ssl->sID);
	if (ssl->pubKey) {
		RSA *rsa = EVP_PKEY_get1_RSA(ssl->pubKey);
		RSA_free(rsa);
		EVP_PKEY_free(ssl->pubKey);
	}
	if (ssl->priKey) { 
		RSA *rsa = EVP_PKEY_get1_RSA(ssl->priKey);
		RSA_free(rsa);
		EVP_PKEY_free(ssl->priKey);
	}
	if (ssl->certX509)
		X509_free(ssl->certX509);
	if (ssl->md5Fin) {
		EVP_MD_CTX_cleanup(ssl->md5Fin);
		free(ssl->md5Fin);
	}
	if (ssl->sha1Fin) {
		EVP_MD_CTX_cleanup(ssl->sha1Fin);
		free(ssl->sha1Fin);
	}
	if (ssl->cipherRCtx) {
		EVP_CIPHER_CTX_cleanup(ssl->cipherRCtx);
		free(ssl->cipherRCtx);
	}
	if (ssl->cipherWCtx) {
		EVP_CIPHER_CTX_cleanup(ssl->cipherWCtx);
		free(ssl->cipherWCtx);
	}
	free(ssl->rawDataBuf);
	CRYPTO_cleanup_all_ex_data();
	EVP_cleanup();
	ERR_free_strings();
	//shutdown(connfd, SHUT_RDWR);
	close(connfd);
	free(ssl);
}

#ifndef _SSL_LIB_H_
#define _SSL_LIB_H_

#include <openssl/x509.h>
#include <openssl/ssl.h>
#include "Common.h"

#define CHECK_HDR(_expect, _actual, _hdr, _bail)					\
	do {															\
		if (_expect != _actual) {									\
			printf("Inconsistent %sT header\n", #_hdr);				\
			printf("Expect:0x%X, Actual:0x%X\n", _expect, _actual);	\
			printf("%s:%d\n", __FILE__, __LINE__);					\
			goto _bail;												\
		}															\
	} while (0)

#define CHECK_VER(_expect, _actual, _hdr, _bail);					\
	do {															\
		if (_expect != _actual) {									\
			printf("Inconsistent %sT version\n", #_hdr);			\
			printf("Expect:0x%X, Actual:0x%X\n", _expect, _actual);	\
			printf("%s:%d\n", __FILE__, __LINE__);					\
			goto _bail;												\
		}															\
	} while (0)

#define CHECK_READ(_expect, _actual, _bail)							\
	do {															\
		if ((_expect) != (_actual)) {								\
			printf("Inconsistent read byte counts\n");				\
			printf("Expect:%d, Actual:%d\n", (_expect), (_actual));	\
			printf("%s:%d\n", __FILE__, __LINE__);					\
			goto _bail;												\
		}															\
	} while (0)

#define FIN_DIGEST_UPDATE(_ptr, _len)				\
	do {											\
		EVP_DigestUpdate(ssl->md5Fin, _ptr, _len);	\
		EVP_DigestUpdate(ssl->sha1Fin, _ptr, _len);	\
	} while (0)


/* SSL options */
/* 
 * Disable SSL 3.0/TLS 1.0 CBC vulnerability workaround that was added
 * in OpenSSL 0.9.6d.  Usually (depending on the application protocol)
 * the workaround is not needed.  Unfortunately some broken SSL/TLS
 * implementations cannot handle it at all, which is why we include
 * it in SSL_OP_ALL. 
 */
#define SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS	0x00000800L

/* SSL version */
#define SSL30_VERSION					0x0300 
#define SSL31_VERSION					0x0301 
#define SSL32_VERSION					0x0302 
#define SSL33_VERSION					0x0303

/* SSL file constants*/
/* record layer type */
#define SSLRTHdr		0x0	// offset to (record layer) header
#define SSLRTVer		0x1 // offset to (record layer) version
#define SSLRTLen		0x3 // offset to (record layer) message length

/* message type */
#define SSLMTHdr		0x5 // offset to (message type) header
#define SSLMTLen		0x6 // offset to (message type) message length

/* message */
#define SSLMsgBody		0x9 // offset to message body

/* header length */
#define SSLRTHdrLen	SSLMTHdr - SSLRTHdr
#define SSLMTHdrLen	SSLMsgBody - SSLMTHdr

/* SSL record layer type header number */
#define	SSL_RT_CHANGE_CIPHER_SPEC			0x14
#define SSL_RT_ALERT						0x15
#define SSL_RT_HANDSHAKE					0x16
#define SSL_RT_APPLICATION_DATA				0x17

/* SSL message type header number */

/* handshake */
#define SSL_MT_HSK_HELLO_REQUEST			0x00
#define SSL_MT_HSK_CLIENT_HELLO				0x01
#define SSL_MT_HSK_SERVER_HELLO				0x02
#define SSL_MT_HSK_CERTIFICATE				0x0B
#define SSL_MT_HSK_SERVER_KEY_EXCHANGE		0x0C
#define SSL_MT_HSK_CERTIFICATE_REQUEST		0x0D
#define SSL_MT_HSK_SERVER_DONE				0x0E
#define SSL_MT_HSK_CERTIFICATE_VERIFY		0x0F
#define SSL_MT_HSK_CLIENT_KEY_EXCHANGE		0x10
#define SSL_MT_HSK_FINISHED					0x14
#define SSL_MT_HSK_SUCCESS					0x15

/* change cipher spec */
#define SSL_MT_CCS							0x01

/* alert */
#define SSL_MT_ALT_CLOSE_NOTIFY				0x00
#define SSL_MT_ALT_UNEXPECTED_MESSAGE		0x0A
#define SSL_MT_ALT_BAD_RECORD_MAC			0x14
#define SSL_MT_ALT_DECOMPRESSION_FAILURE	0x1E
#define SSL_MT_ALT_HANDSHAKE_FAILURE		0x28
#define SSL_MT_ALT_NO_CERTIFICATE			0x29
#define SSL_MT_ALT_BAD_CERTIFICATE			0x2A
#define SSL_MT_ALT_UNSUPPORTED_CERTIFICATE	0x2B
#define SSL_MT_ALT_CERTIFICATE_REVOKED		0x2C
#define SSL_MT_ALT_CERTIFICATE_EXPIRED		0x2D
#define SSL_MT_ALT_CERTIFICATE_UNKNOWN		0x2E
#define SSL_MT_ALT_ILLEGAL_PARAMETER		0x2F

#define MASTER_SECRET_SIZE				48
#define PRE_MASTER_SECRET_SIZE			48

#define SERVER_RANDOM_SIZE				32
#define CLIENT_RANDOM_SIZE				32

#define TLS_VERIFY_DATA_SIZE			12
#define TLS_MAX_CONST_SIZE				20
#define TLS_CLIENT_FINISH_CONST			"client finished"
#define TLS_CLIENT_FINISH_CONST_SIZE    15
#define TLS_SERVER_FINISH_CONST			"server finished"
#define TLS_SERVER_FINISH_CONST_SIZE    15
#define TLS_SERVER_WRITE_KEY_CONST      "server write key"
#define TLS_SERVER_WRITE_KEY_CONST_SIZE 16
#define TLS_KEY_EXPANSION_CONST			"key expansion"
#define TLS_KEY_EXPANSION_CONST_SIZE    13
#define TLS_CLIENT_WRITE_KEY_CONST      "client write key"
#define TLS_CLIENT_WRITE_KEY_CONST_SIZE 16
#define TLS_SERVER_WRITE_KEY_CONST      "server write key"
#define TLS_SERVER_WRITE_KEY_CONST_SIZE 16
#define TLS_IV_BLOCK_CONST				"IV block"
#define TLS_IV_BLOCK_CONST_SIZE			8
#define TLS_MASTER_SECRET_CONST			"master secret"
#define TLS_MASTER_SECRET_CONST_SIZE    13

struct SSL_METH; 
/*
 * Information of the symmetric ciphers
 */
typedef struct SymCipher {
	char *name;
	int keyMaterial;
	int keyMaterialExp;
	int keyBitsEff;
	int ivSize;
	int blockSize;
	bool isExportable;
} SymCipher;

extern SymCipher symCipherTable[];

typedef struct CipherSuite {
	char *name;
	int ID;
	/* symmetric-key algorithm callback function */
	const EVP_CIPHER *(*cipherCB)(void);
	/* cipher structure */
	EVP_CIPHER *cipher;
	/* digest callback function*/
	const EVP_MD *(*digestCB)(void);
	/* digest structure */
	EVP_MD *digest;
	/* 
	 * the number of bytes from the key_block that are
	 * used for generating the write keys
	 */
	int keyMaterial;
	bool isExport;
} CipherSuite;

extern CipherSuite cipherTable[];

typedef	struct KeyPairs {
	/* binary data of all keys */
	u1 *data;
	/* separate key pointer */
	u1 *clientMAC;
	u1 *serverMAC;
	u1 *clientW;
	u1 *serverW;
	u1 *clientIV;
	u1 *serverIV;
} KeyPairs;

typedef struct SSLSession {
	int connfd;
	u1 *clnRandom;
	u1 *svrRandom;
	int sIDLen;
	char *sID;
	/* Data buffer used to send/receive packet to from socket */
	u1 *rawDataBuf;
	/* How many pending raw data wait to be read and processed */
	int rawDataLen;
	/* How many raw data has been read and processed */
	int rawDataRead;
	/* Compression method during connection */
	int compression;
	/* The real cipher suite used in session*/
	CipherSuite *cs;	
	
	/*Certificate information*/
	X509 *certX509;

	/* 
	 * Public key information, taken after certificate.
	 * This key is only used by client.
	 */
	EVP_PKEY *pubKey;

	/* 
	 * Private key information, taken after sslInit.
	 * This key is only used by server.
	 */
	EVP_PKEY *priKey;
	/* 
	 * Secret information for generating key pairs. This 
	 * information is computed from pre_master_secret and
	 * can be cached for session resumption.
	 */
	u1 *masterSecret;
	/*
	 * Key pairs for doing symmetric-key encryption/decryption
	 */
	KeyPairs *keys;
	/*
	 * digest context for computing finished message
	 */
	EVP_MD_CTX *md5Fin;
	EVP_MD_CTX *sha1Fin;
	/*
	 * cipher context for session messages encryption/decryption
	 */
	EVP_CIPHER_CTX *cipherRCtx;
	EVP_CIPHER_CTX *cipherWCtx;
	/* session sequence number for computing MAC */
	u8 svrSeq;
	u8 clnSeq;
	/* options for this SSL session */
	u8 options;

	/* ssl related methods */
	struct SSL_METH *method;
	/* is in encryption mode */
	bool inEnc;
} SSLSession;

typedef struct SSL_METH {
	int (*handshake)(SSLSession*, bool);
	int (*version)(void);
} SSL_METH;

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
			u1 *data, u2 dataLen, u1 *out);

/*
 * Generate a digest of all previous handshake messages
 * for verification. Original context can't be finalize
 * because this function will occur twice.
 */
void genFinMsg(SSLSession *ssl, u1 *label, int labelLen, 
			   u1 *out, int outLen, int version);

/* 
 * Generate master_secret from pre_master_secret 
 * and return it. 
 */
u1 *genMasterSecret(SSLSession *ssl, u1 *preMS, int version);

/*
 *
 */
KeyPairs *genKeyPairs(SSLSession *ssl, int version);

/*
 *
 */
CipherSuite *getCipherByID(u4 cipherID);

/*
 * Real function which is used to read ssl packet from socket 
 * and write to message buffer for further processing. On success, 
 * number of received bytes will be returned, else -1 will be 
 * returned.
 */
int sslRecvPacket(SSLSession *ssl, int sslRT, int sslVer, 
				  FILE *logFile);

/*
 * Real function which is used to write ssl packet header and 
 * send it to socket. On success, number of received bytes will 
 * be returned, else -1 will be returned.
 */
int sslSendPacket(SSLSession *ssl, int sslRT, int sslVer, 
				  int sslMTLen, FILE *logFile);

/*
 *
 */
int sslCBCPadding(SSLSession *ssl, u1 *plainTail, int plainLen);

/*
 * This function combines HMAC generation and message encryption for
 * the plainText before sending to receiver. Thus, it can be used only 
 * after session encryption key is computed. On success, length of 
 * cipherText will be returned and the encrypted data will be put in 
 * cipherText, else 0 will be returned.
 * 
 * Warning:
 * plainText must have enough space for (plainText || HMAC), else
 * buffer overflow may occur.
 */
int sslSessionEnc(SSLSession *ssl, u1 *plainText, int plainLen, 
				  u1 *cipherText, int sslRT, int sslVer, int which);

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
				  u1 *plainText, int sslRT, int sslVer, int which);

/*
 * This function read and check the message type header and return 
 * the address of the message body. The msgLen argument will be 
 * filled with the length of the message body. Finally, the whole
 * message will be digested for generating the verify data in finished
 * message.
 */
u1* sslReadMTHdr(SSLSession *ssl, int *msgLen, int sslMT, int sslVer);

/*
 * This function fill the message header with type and length. The
 * whole message length (i.e. message header and message body) will 
 * be returned. Finally, the whole message will be digested for 
 * generating the verify data in finished message.
 */
int sslWriteMTHdr(SSLSession *ssl, int msgLen, int sslMT, int sslVer);

/*
 * Initialize the ssl table
 */
SSLSession* sslInit(int connfd, CmdTable *cmds, int which);

/*
 * Cleanup the ssl table
 */
void sslClean(SSLSession *ssl, int connfd, int which);

/* 
 * Generate a stream of random numbers with number 
 * of bytes and return the generated stream.
 */
u1 *genRandom(int byte);

#endif

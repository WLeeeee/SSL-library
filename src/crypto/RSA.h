#ifndef _RSA_H
#define _RSA_H
#include <gmp.h>
#include "../Common.h"

typedef struct RSAParameters {
	int keyLen;
	u1 *pbKey;
	mpz_t pbKey_z; 
	u1 *pvKey;
	mpz_t pvKey_z;
	u1 *mod;
	mpz_t mod_z;
} RSAParameters;

typedef struct RSAFiles {
	FILE *pbKey_f;
	FILE *pvKey_f;
	FILE *mod_f;
	FILE *cipher_f;
	FILE *plain_f;
} RSAFiles;

int rsaEncrypt(RSAParameters *rsa, u1 *cipher, u1 *plain);

int rsaDecrypt(RSAParameters *rsa, u1 *cipher, u1 *plain);

bool rsaVerify();

void rsaEncryptCb();

void rsaDecryptCb();

#endif

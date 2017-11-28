#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include "RSA.h"

/*
 * The GNU MP library is used here for facilitating
 * RSA encryption/decryption because big number modulus
 * is a very difficult computation.
 */

static u1 *rsaRaw2Str(u1 *rawIn, int length)
{
	u1 *out, *pOut;
	int i;
	char map[] = "0123456789ABCDEF";

	if (length == 0)
		return NULL;

	pOut = out = (u1 *) calloc(length * 2 + 1, sizeof(u1));
	
	for (i=0; i<length; i++) {
		*pOut++ = map[((*rawIn) & 0xF0) >> 4];
		*pOut++ = map[((*rawIn) & 0x0F)];
		rawIn++;
	}

	return out;
}
static char rsaChar2Hex(char ch)
{
	if (ch >=0 && ch <= 9) {
		return ch - '0';
	} else if (ch >= 'A' && ch <= 'F') {
		return ch - 55;
	} else if (ch >= 'a' && ch <= 'f') {
		return ch - 87;
	} else {
		return 0xFF;
	}
}
static u1 *rsaStr2Raw(u1 *strIn, int length)
{
	u1 *out = NULL, *pOut;
	u1 hex = 0;

	if (length == 0)
		goto bail;

	pOut = out = (u1 *) calloc((length+1) >> 1, sizeof(u1));

	/* length is odd */
	if ((length & 0x1) != 0) {
		if ((hex = rsaChar2Hex(*strIn++)) == 0xFF)
			goto bail;
		(*pOut) |= hex;
		length--;
		pOut++;
	}
	int i;
	for (i=0; i<length; i++) {
		if ((hex = rsaChar2Hex(*strIn++)) == 0xFF)
			goto bail;
		*pOut |= (rsaChar2Hex(*strIn++) << 4);
		if ((hex = rsaChar2Hex(*strIn++)) == 0xFF)
			goto bail;
		*pOut |= rsaChar2Hex(*strIn++);
		pOut++;
	}

bail:
	if (hex == 0xFF) { // failed
		printf("Invalid char exists in rsa string\n");
		free(out);
		out = NULL;
	}
	return out;
}
/*
 * Function for getting key length, in bytes.
 */
static int rsaGetKeyLen(u1 *mod, int modLen)
{
	if ((modLen & 0x1) != 0) {
		if (*mod == '0') {
			mod++;
			modLen--;
		} else {
			return ((modLen + 1) >> 1);
		}
	}
	while (*mod == '0' && *(mod+1) == '0') {
		mod += 2;
		modLen -= 2;
	}
	return (modLen >> 1);
}
/*
 * This function is used to initialize the data structure used
 * by encryption/decryption.
 */
RSAParameters *rsaInit(u1 *pvKey, int pvLen, 
					   u1 *pbKey, int pbLen, 
					   u1 *mod, int modLen)
{
	RSAParameters *rsa = NULL;

	rsa = (RSAParameters *) malloc(sizeof(RSAParameters));
	
	/* calculate key length */
	rsa->keyLen = rsaGetKeyLen(mod, modLen);
	
	/* initialize */
	mpz_init(rsa->pbKey_z);
	mpz_init(rsa->pvKey_z);
	mpz_init(rsa->mod_z);

	mpz_set_str(rsa->mod_z, (char *)mod, 16);
	mpz_set_str(rsa->pbKey_z, (char *)pbKey, 16);
	mpz_set_str(rsa->pvKey_z, (char *)pvKey, 16);

	return rsa;
}

int rsaEncrypt(RSAParameters *rsa, u1 *cipher, u1 *plain)
{
	return 0;
}

/*
 * Low level rsa decryption function. Input is string data. 
 * After decryption, the decrypted string data will be
 * put in plain and string length will be returned.
 */
int rsaDecrypt(RSAParameters *rsa, u1 *cipher, u1 *plain)
{
	mpz_t cipher_z, plain_z;
	u1 plainStr[1024];

	mpz_init(plain_z);
	mpz_init(cipher_z);

	mpz_set_str(cipher_z, (char *)cipher, 16);

	mpz_powm(plain_z, cipher_z, rsa->pvKey_z, rsa->mod_z);
	//mpz_get_str((char *)plainStr, 16, plain_z);
	mpz_get_str((char *)plainStr, 16, plain_z);
	int i;

	printf("a\n");
	for (i=0; i<256; i++) {
		printf("%c", plainStr[i]);
	}
	printf("b\n");
	printf("\n");
	/* trimming padding, currently only PKCS#1 is supported */
	/*
	u1 *pStr = plainStr;
	pStr += 4;
	for (i=0; i<rsa->keyLen; i+=2) {
		if (*pStr == '0' && *(pStr+1) == '0') {
			pStr += 2;
			break;
		}
	}
	memcpy(plain, pStr, rsa->keyLen-i);
*/
	return 0;
	//return rsa->keyLen - i;
}

bool rsaVerify()
{
	int cc = -1;

	return cc;
}

void rsaEncryptCb()
{

}

void rsaDecryptCb()
{
	/*
	RSAFiles *files = 
		(RSAFiles *)sslTable.cryptoFiles;

	u1 pvKey[1024];
	int pvKeyLen;
	u1 mod[1024];
	int modLen;
	u1 cipher[512];

	pvKeyLen = fread(pvKey, sizeof(u1), 512, files->pvKey_f);
	modLen = fread(mod, sizeof(u1), 512, files->mod_f);

	RSAParameters *rsa = 
		rsaInit(pvKey, pvKeyLen, pvKey, 0, mod, modLen);
*/
}


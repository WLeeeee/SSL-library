#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "MD5.h"
#include "../../utils/BitOp.h"
/* 
 * Based on RFC-1321
 * The i-th element of this table is computed by 2^32 * abs(sin(i))
 * where i is in radians(i*(180/pi)).
 */
u4 MD5LookupTab[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

/* 
 * Based on RFC-1321 
 * The shift table for storing the per-round shifting bits.
 */
u4 MD5ShiftTab[64] = {
	 7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
	 5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
	 4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
	 6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};
/* 
 * Definition of auxiliary functions 
 * All of these functions are defined in rfc-1321
 */
#define AUX_F(_x, _y, _z)	\
	(((_x) & (_y)) | ((~_x) & (_z)))

#define AUX_G(_x, _y, _z)	\
	((_x) & (_z)) | ((_y) & (~_z))

#define AUX_H(_x, _y, _z)	\
	(_x) ^ (_y) ^ (_z)

#define AUX_I(_x, _y, _z)	\
	(_y) ^ ((_x) | (~_z))
/*
 * Core MD5 hash function
 * Default chunk size handled by this function is 64 bytes (512 bits).
 */
static int runMD5Hash(MD5Ctx *ctx)
{
	int i, j;
	u4 aux, x[16];
	u4 *pData = &(ctx->data[0]);
	u4 rA, rB, rC, rD;  
	
	if (ctx == NULL) {
		printf("Error: MD5 context is NULL\n");
		return 0;
	}

	rA = ctx->regs[0];
	rB = ctx->regs[1]; 
	rC = ctx->regs[2]; 
	rD = ctx->regs[3];
	
	u1 *pSrc = (u1 *)(&pData[0]);

	for (i=0; i<64; i++) {
		if (i >= 0 && i < 16) {
			j = i;
			aux = AUX_F(rB, rC, rD);
		} else if (i >= 16 && i < 32) {
			j = (i * 5 + 1) % 16;
			aux = AUX_G(rB, rC, rD);
		} else if (i >= 32 && i < 48) {
			j = (i * 3 + 5) % 16;
			aux = AUX_H(rB, rC, rD);
		} else {
			j = (i * 7) % 16;
			aux = AUX_I(rB, rC, rD);
		}
		int temp = rD;

		rD = rC;
		rC = rB;
		rB = rB + 
			 LEFT_ROTATE((rA+aux+pData[j]+MD5LookupTab[i]), MD5ShiftTab[i]);
		rA = temp;
	}
	
	ctx->regs[0] += rA;
	ctx->regs[1] += rB;
	ctx->regs[2] += rC;
	ctx->regs[3] += rD;

	return 1;
}

/*
 * Do MD5 context initialization
 */
int initMD5(MD5Ctx *ctx)
{
	if (ctx == NULL)
		return 0;

	ctx->regs[0] = 0x67452301;
	ctx->regs[1] = 0xEFCDAB89;
	ctx->regs[2] = 0x98BADCFE;
	ctx->regs[3] = 0x10325476;
	ctx->length = 0;
	ctx->dataIdx = 0;

	return 1;
}

/*
 * Update the current data to the computed MD5 context
 */
int updateMD5(MD5Ctx *ctx, const char *src, int len)
{
	const char *pSrc = src;
	char *pDst = (char *)(&ctx->data[0]);

	ctx->length += len;

	while (len > 0) {
		/* One MD5 chunk is 4 bytes */
		int cpLen = (MD5_CHUNK_COUNT * MD5_CHUNK_SIZE) - ctx->dataIdx;

		cpLen = (len >= cpLen) ? cpLen : len;
		memcpy(pDst+ctx->dataIdx, pSrc, cpLen);
		len -= cpLen;
		ctx->dataIdx += cpLen;

		/* 
		 * If data is full, do hash, else current data will be 
		 * combined with next data
		 */
		if (ctx->dataIdx == (MD5_CHUNK_COUNT * MD5_CHUNK_SIZE)) {
			if (!runMD5Hash(ctx)) {
				printf("Error:MD5 update failed\n");
				return 0;
			}
			ctx->dataIdx = 0;
		}
		pSrc += cpLen;
	}
	return 1;
}

int finMD5(char *dst, MD5Ctx *ctx)
{
	char *pSrc = (char *)(&ctx->data[0]) ;

	memset(pSrc + ctx->dataIdx, 0, MD5_CHUNK_COUNT * MD5_CHUNK_SIZE - ctx->dataIdx);
	*(pSrc + ctx->dataIdx) = 0x80;

	/* 
	 * Current chunk space is insufficient to store message bit count.
	 * Do one more hash and add padding zero bits.
	 */
	if ((MD5_CHUNK_COUNT * MD5_CHUNK_SIZE - ctx->dataIdx) < 8) {
		if (runMD5Hash(ctx) < 0) 
			goto bail;

		memset(pSrc, 0, MD5_CHUNK_COUNT * MD5_CHUNK_SIZE - 8);
	}
	/* Add message bit count and do final hash */
	*((u8 *)(&ctx->data[MD5_CHUNK_COUNT-2])) = ctx->length * 8;

	if (runMD5Hash(ctx) < 0)
		goto bail;

	memcpy(dst, (char *)(&ctx->regs[0]), MD5_HASH_SIZE);
	
	return 1;
bail:
	printf("Error:MD5 finalize error\n");
	return 0;
}

char* doMD5(char *dst, const char *src, int len)
{
	MD5Ctx ctx;

	if (initMD5(&ctx) < 0)
		goto bail;

	if (updateMD5(&ctx, src, len) < 0)
		goto bail;

	if (finMD5(dst, &ctx) < 0)
		goto bail;

	return dst;
bail:
	printf("Error:MD5 hashing failed\n");
	return NULL;
}


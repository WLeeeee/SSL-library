#include "../../Common.h"

#define MD5_HASH_SIZE	16
#define MD5_CHUNK_SIZE	4	
#define MD5_CHUNK_COUNT	16	

typedef struct MD5Ctx {
	/* Register [A, B, C, D] for storing current hashing results */
	u4 regs[4];
	/* Data which is not hashed yet */
	u4 data[MD5_CHUNK_COUNT];
	/* Index to the data field, in byte */
	u4 dataIdx;
	/* Current hashed length */
	u8 length;
} MD5Ctx;

int initMD5(MD5Ctx *ctx);
int updateMD5(MD5Ctx *ctx, const char *src, int len);
int finMD5(char *dst, MD5Ctx *ctx);
char* doMD5(char *dst, const char *src, int len);

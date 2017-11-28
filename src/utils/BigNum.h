#ifndef _BIG_NUM_H_
#define _BIG_NUM_H_

#include "../Common.h"

/* The max number of digits for a storable hexdecimal number */
#define BNUM_HEX_MAX_DIGITS	2048	

/* Every position can store up to 8 digits in hexdecimal */
#define BNUM_HEX_DIGITS_PER_POS	8

typedef struct BNum {
	/* For storing the real big number */
	u4 num[BNUM_HEX_MAX_DIGITS/BNUM_HEX_DIGITS_PER_POS];
	/* Index of current big number position plus one */
	u4 index;
	/**/
	char sign;
	int base;
} BNum;

int setStr2BNum(BNum *pNum, char *pStr, int base);
int initBNum(BNum *src);
BNum *addBNum(BNum *pDst, BNum *pSrc1, BNum *pSrc2);
BNum *subBNum();
BNum *mulBNum(BNum *dst, BNum *src1, BNum *src2);
BNum *divBNum();
char *printBNum2Str(BNum *src, char *dst, int base);

#endif

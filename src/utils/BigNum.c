#include <string.h>
#include <stdio.h>
#include "BitOp.h"
#include "BigNum.h"
#include "StrLib.h"

static char *hex2Dec(BNum *src, char *dst)
{
	u4 bigNum[160] = {0}, bIdx = 1;
	u4 tmp;
	int i;

	for (i=src->index-1; i>=0; i--) {
		/*
		 * Step 1:
		 * Every position's word is reversed.
		 * For example:
		 * ABCD1234 12345678 -> 4321DCBA 87654321
		 * Doing such transformation will help us to convert
		 * hexdecimal number to decimal in more convenient
		 * manner.
		 */
		tmp = (u4) reverseWord(src->num[i], 4);
		/*
		 * Step 2:
		 * For every reversed word, we get the last four bits
		 * and do hex to dec computation
		 * Every position can only store 8 digits
		 */
		while (tmp != 0) {
			bigNum[0] += (tmp & 0xF);
			tmp >>= 4;
			
			/* final hex, don't do multiplication and check carry */
			if (i == 0 && tmp == 0)
				goto handle_carry;

			int j, carry;
			for (j=0; j<bIdx; j++) {
				bigNum[j] = bigNum[j] * 16;
			}

handle_carry:
			/* 
			 * Handle carry. bIdx should be increased if the number of 
			 * final position is larger than 8 digits
			 */
			for(j=0, carry=0; j<bIdx || carry!=0; j++) {
				bigNum[j] += carry;
				carry = bigNum[j] / 100000000;
				bigNum[j] = bigNum[j] % 100000000;
			}

			if (j > bIdx)
				bIdx = j;
		}
	}
	/*
	 * Step 3:
	 * Convert final result to char string
	 */
	int k;
	printf("%d", bigNum[bIdx-1]);
	for (k=bIdx-2; k>=0; k--) {
		printf("%06d", bigNum[k]);
	}
	printf("\n");
}

static int cmpBNum(BNum *src1, BNum *src2)
{
	if (src1->index != src2->index)
		return (src1->index > src2->index) ? 1 : -1;
	
	int i;
	for (i=src1->index; i>=0; i--) {
		if (src1->num[i] != src2->num[i])
			return (src1->num[i] > src2->num[i]) ? 1 : -1;
	}

	return 0;
}

/* 
 * Because only hexdecimal number needs to be handled on internet,
 *  we only handle number with base 16 
 */
int setStr2BNum(BNum *pNum, char *str, int base)
{
	char *pStr = str + strlen(str);

	if (base != 16) {
		printf("Error: Big number library for SSL can only "
			"handle number with base 16\n");
		return -1;
	}

	int i, j;

	for (i=0, j=0; pStr!=str; j++, pStr--) {
		pNum->num[i] |= CHAR2HEX(*(pStr-1)) << (j * 4);
		if (j == 7) {
			i++;
			j = -1;
		}	
	}
	if (pNum->num[i] == 0)
		pNum->index = i;
	else
		pNum->index = i+1;
}

int initBNum(BNum *src)
{
	if (src == NULL) {
		printf("Error: BigNum initialize failed\n");
		return 0;
	}

	memset(src, 0, sizeof(BNum));

	return 1;
}
/*
 * pSrc1: A quantity to which the addend is added, i.e. augend
 * pSrc2: Any of a set of numbers to be added, i.e. addend
 * pDst: Summation result of two sources 
 * retern value: Same as pDst
 */
BNum *addBNum(BNum *pDst, BNum *pSrc1, BNum *pSrc2)
{
	int i, carry;

	if (pSrc1->sign != pSrc2->sign) {
		if (pSrc1->sign == '-') {
			pSrc1->sign == '+';
//			pDst = subBNum(pDst, pSrc2, pSrc1);
			pSrc1->sign == '-';
		} else {
			pSrc2->sign == '+';
//			pDst = subBNum(pDst, pSrc1, pSrc2);
			pSrc2->sign == '-';
		}
		return pDst;
	}

	/* This operation must be done with to operators with the same sign */
	for (i=0, pDst->index=pSrc1->index; i<pSrc1->index; i++) {
		pDst->num[i] = pSrc1->num[i];
	}

	for (i=0; i<pSrc2->index; i++) {
		pDst->num[i] += pSrc2->num[i];
		
		if (pDst->num[i] < pSrc2->num[i]) { /* carry */
			pDst->num[i+1] = 0x1;
		}
	}

	if (pSrc2->index > pDst->index) {
		pDst->index = pSrc2->index;
	}

	return pDst;
}

BNum *mulBNum(BNum *dst, BNum *src1, BNum *src2)
{
	int i, j;
	u4 carry;
	
	for (i=0; i<src2->index; i++) {
		u8 result1 = 0, result2 = 0;
		for (carry=0, j=0; j<src1->index; j++) {
			result1 = (u8)src2->num[i] * (u8)src1->num[j];
			result2 = (u8)dst->num[i+j] + (u8)(result1 & 0xFFFFFFFF) + 
					  (u8)carry + (u8)(result2 >> 32);

			dst->num[i+j] = result2 & 0xFFFFFFFF;
				
			carry = result1 >> 32;
		}
		dst->num[i+j] = carry + (result2 >> 32);

	}
	
	if (dst->num[i+j-1] != 0) {
		dst->index = i + j;
	} else
		dst->index = i + j - 1;
}

BNum *divBNum(BNum *dst, BNum *src1, BNum *src2)
{
	int idx1 = src1->index, idx2 = src2->index;

	src1->index = (idx1-1) * 8 + 
}
BNum *modBNum(BNum *dst, BNum *src1, BNum *src2)
{
}

char *printBNum2Str(BNum *src, char *dst, int base)
{
	
}

#include <string.h>
#include "Base64.h"
#include "../utils/FileIO.h"

#define LINE_MAX_DIGITS 64

/*
 * This table is used for encoding. In encoding step, every three
 * 8-bit characters will be kroken to a group of four 6-bit index
 * numbers. Then the encoded character will base on these numbers.
 *
 * Example:
 * 10100110 01011001 11101100 -->  101001 100101 100111 101100
 */
char *base64EncodeTable = 
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\0";

/*
 * This is the ASCII table from the 1st character to 123th character.
 * This table is used by decoding step to find the index of every
 * encoded character in base64EncodeTable.
 *
 * ASCII Sequence: (+) (/) (0-9) (A-Z) (a-z)
 */
const int base64DecodeTable[123] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF,   62, 0xFF, 0xFF, 0xFF,   63,   52,   53,
	  54,   55,   56,   57,   58,   59,   60,   61, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF,    0,    1,    2,    3,    4, 
	   5,    6,    7,    8,    9,   10,   11,   12,   13,   14, 
	  15,   16,   17,   18,   19,   20,   21,   22,   23,   24,
	  25, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   26,   27,   28,
	  29,   30,   31,   32,   33,   34,   35,   36,   37,   38,
	  39,   40,   41,   42,   43,   44,   45,   46,   47,   48,
	  49,   50,   51,
};

/* 
 * Basic base64 encoding function, which encodes char *in 
 * buffer. On success, encoded result will be put in a 
 * newly allocated buffer, then returned, else NULL will 
 * be returned.
 */
u1* base64Encode(u1 *in)
{
	int leftChar; // how many characters remain for processing
	int outLen;
	u1 *out = NULL, *pOut;

	if (in == NULL) {
		printf("No input for encoding\n");
		goto bail;
	}

	leftChar = strlen((char *)in);
	outLen = ((leftChar / 3) * 4) + (((leftChar % 3) != 0) * 4);
	/* add line feed('\n') after encoding 64 bits and last line*/
	outLen += ((outLen-1) / 64) + 1; 
	pOut = out = (u1 *) malloc(sizeof(u1) * outLen);

	int lineDigits = 0;
	while (leftChar > 0) {
		int group = 0, mask = 0x00FC0000;
		int i;
		if (leftChar > 2) {
			/* more than 3 characters remain */
			in += readBE(in, &group, 3);
			i = 3;
		} else {
			/* Only 1 or 2 characters remain */
			mask >>= ((2 / leftChar) * 6);
			readBE(in, &group, leftChar);
			group <<= (4 / leftChar);
			i = leftChar;
		}
		for (; i>=0; i--) {
			u1 encIndex = (u1)((group & mask) >> (i * 6));
			*pOut = base64EncodeTable[(u4)encIndex];
			pOut++;
			mask >>= 6;
		}
		leftChar -= 3;
		/* 
		 * Check if a single line reachs maximum digit number.
		 * If yes, add one line feed('\n') to the end of line.
		 */
		lineDigits += 4;
		if (lineDigits == LINE_MAX_DIGITS && leftChar > 0) {
			lineDigits = 0;
			*pOut = '\n';
			pOut++;
		}
	}
	/* padding */
	for (;leftChar<0;leftChar++, pOut++) {
		*pOut = '=';
	}
	*pOut = '\n';
bail:
	return out;
}

/* 
 * Basic base64 decoding function, which decodes char *in 
 * buffer. On success, decoded result will be put in a 
 * newly allocated buffer, then returned, else NULL will 
 * be returned.
 */
u1* base64Decode(u1 *in)
{
	int leftChar; // how many characters remain for processing
	int outLen = 0;
	u1 *out = NULL, *pOut;

	if (in == NULL) {
		printf("No input for decoding\n");
		goto bail;
	}

	leftChar = strlen((char *)in) - 1;	// delete last line feed
	/* Computing line feed('\n') after encoding 64 bits and last line*/
	int numLF = ((leftChar-1) / 64) ;
	/* Computing padding. Only 1 or 2 padding */
	int padding = (in[leftChar-1] == '=') + (in[leftChar-2] == '=');
	/* 
	 * Computing decoded length after deleting line feed and padding 
	 * and add one terminating character('\0').
	 */
	outLen = (((leftChar-numLF) / 4) * 3) - padding + 1;
	pOut = out = (u1 *) malloc(sizeof(u1) * outLen);

	int lineDigits = 0;
	while (leftChar > 0) {
		u4 encGroup = 0, encMask = 0xFF000000;
		u4 decGroup = 0, decMask = 0x00FF0000;
		int procDigits;
		if (leftChar > 4) {
			/* More than four characters remain */
			procDigits = 4;
			in += readBE(in, (int *)&encGroup, 4);
		} else {
			/* Four characters remain */
			procDigits = 4 - padding;
			readBE(in, (int *)&encGroup, procDigits);
			encMask >>= (padding << 3);
			decMask >>= (padding << 3);
		}
		int i;
		/* 
		 * Processing encoded digits, four digits form a group.
		 * This step combines four encoded characters into 1 24-bit
		 * integer for next step.
		 */
		for (i=procDigits-1; i>=0; i--) {
			u4 decIndex = (encGroup & encMask) >> (i << 3);
			/* TODO: error checking */
			decGroup |= base64DecodeTable[decIndex] << (i * 6);
			encMask >>= 8;
		}
		/* Handling padding if 4 characters remain */
		decGroup >>= ((leftChar == 4) * (padding * 2));
		/* 
		 * processing decoded digits, three digits form a group.
		 * This steps breaks the 24-bit integer to three different
		 * characters, then write every decoded character to out buffer.
		 */
		for (i=procDigits-2; i>=0; i--) {
			*pOut = (decGroup & decMask) >> (i << 3);
			pOut++;
			decMask >>= 8;
		}
		leftChar -= 4;
		lineDigits += 4;
		/* 
		 * Check if a single line reachs maximum digit number.
		 * If yes, ignore one line feed('\n') at the end of line.
		 */
		if (lineDigits == LINE_MAX_DIGITS && leftChar > 0) {
			in++;
			lineDigits = 0;
			leftChar--;
		}
	}
bail:
	return out;
}


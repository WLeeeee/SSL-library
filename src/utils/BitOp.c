#include "BitOp.h"

/* 
 * By xor operation, input number will be half-byte reversed.
 * Input size must be 2, 4, 8 or 16
 * For example:
 * 0xABCDABCD will be transformed to
 * 0xDCBADCBA
 */
u8 reverseWord(u8 in, int size)
{
	int i;
	u8 out = in;
	u1 tmp, *ptr = (u1 *)(&out);

	/* 1: Do byte reverse */
	for (i=0; i<4; i++) {
		tmp = ptr[i] ^ ptr[7-i];
		ptr[i] = tmp ^ ptr[i];
		ptr[7-i] = tmp ^ ptr[7-i];
	}
	/* 2: Do half-byte reverse */
	
	for (i=0; i<8; i++) {
		tmp = ((ptr[i] & 0xF) << 4) | ((ptr[i] & 0xF0) >> 4);
		ptr[i] = tmp;
	}

	return out >> ((8-size)*8);
}

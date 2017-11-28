#include "StrLib.h"

u1 *raw2Str(u1 *rawIn, int length)
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

u1 *str2Raw(u1 *strIn, int length)
{
	u1 *out = NULL, *pOut;
	u1 hex = 0;

	if (length == 0)
		goto bail;

	pOut = out = (u1 *) calloc((length+1) >> 1, sizeof(u1));

	/* length is odd */
	if ((length & 0x1) != 0) {
		if ((hex = char2Hex(*strIn++)) == 0xFF)
			goto bail;
		(*pOut) |= hex;
		length--;
		pOut++;
	}
	int i;
	for (i=0; i<length; i++) {
		if ((hex = char2Hex(*strIn++)) == 0xFF)
			goto bail;
		*pOut |= (char2Hex(*strIn++) << 4);
		if ((hex = char2Hex(*strIn++)) == 0xFF)
			goto bail;
		*pOut |= char2Hex(*strIn++);
		pOut++;
	}

bail:
	if (hex == 0xFF) { // failed
		printf("Invalid char exists in string\n");
		free(out);
		out = NULL;
	}
	return out;
}




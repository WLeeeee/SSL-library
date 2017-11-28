#include "MD5.h"

int main()
{
	MD5Ctx ctx;
	unsigned char data[16];

	doMD5(data, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 64);

	int i;

	for (i=0; i<16; i++) {
		printf("%02x", data[i]);
	}
	printf("\n");
}

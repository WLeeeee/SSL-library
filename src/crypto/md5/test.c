#include <openssl/md5.h>

int main()
{
	MD5_CTX ctx;
	unsigned char data[16];

	MD5_Init(&ctx);
	MD5_Update(&ctx, "A", 1);
	MD5_Final(data, &ctx);

	int i;

	for (i=0; i<16; i++) {
		printf("%x", data[i]);
	}
	printf("\n");
}

#include <stdio.h>

char buf[8192];

int main()
{
	FILE *f = fopen("sb.jpg", "r");
	int i, j;

	j = fread(buf, 1, sizeof(buf), f);

	for (i=0; i<j; i++) {
		printf("%x", (unsigned char)buf[i]);
	}

	printf("\n");
	return 0;
}

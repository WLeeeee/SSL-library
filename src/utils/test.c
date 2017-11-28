#include "BitOp.h"
#include "BigNum.h"
#include "StrLib.h"
#include <gmp.h>
#include <stdio.h>

int main()
{
	BNum bnum1, bnum2, bdst;
	char str1[500] = "10000000000000fffffffffffffffffffffffffffffffffffffffff00000000111abcdabcdabcdabcd00000000000000000000000000000000000000ffffffffffffffffffffff000111111111111111111111111111111111111111111111111111111111111111111111111111111";
	char str2[1000] = "1fffffffffffffffffffffffffffffffffffffffffffffffffffaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbccccccccccccccccccccccccccccccccccccccccccccccccccccccccddddddddddddddddddddddddddddddddddddddddddddddddddfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffabcdacdbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbaaaaaaaa00000000000000000000000000000000000000000000000000000000000000000ff1"; 

	initBNum(&bnum1);	
	initBNum(&bnum2);
	initBNum(&bdst);
	setStr2BNum(&bnum1, str1, 16);
	setStr2BNum(&bnum2, str2, 16);

	mulBNum(&bdst, &bnum1, &bnum2);

	mpz_t a, b, c;

	mpz_init(a);
	mpz_init(b);
	mpz_init(c);

	mpz_set_str(a, str1, 16);
	mpz_set_str(b, str2, 16);

	mpz_mul(c, a, b);

	mpz_out_str(stdout, 16, c);
	printf("\n");
}

#ifndef _BASE_64_H
#define _BASE_64_H
#include "../Common.h"

extern const char *base64IndexTable;

/* 
 * Basic base64 encoding function, which encodes char *in 
 * buffer. On success, encoded result will be put in a 
 * newly allocated buffer, then returned, else NULL will 
 * be returned.
 */
u1* base64Encode(u1 *in);

/* 
 * Basic base64 decoding function, which decodes char *in 
 * buffer. On success, decoded result will be put in a 
 * newly allocated buffer, then returned, else NULL will 
 * be returned.
 */
u1* base64Decode(u1 *in);

int base64EncodeStdio();

int base64DecodeStdio();

#endif

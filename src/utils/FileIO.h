#ifndef _UTILITY_H_
#define _UTILITY_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>

#include "../Common.h"

/* 
 * Write up to "count" of elements from source "arr" to "dst" with 
 * big endian format. Argument "size" means the size of every element 
 * in array and its value must be between 1 to 8.
 */
int writeArrBE(u1 *dst, u1 *arr, int size, int count);

/* 
 * Write number of bytes int source to char* destination, 
 * with big endian form.
 */
int writeBE(u1 *dst, u8 src, int bytes);

/*
 * Write up to count bytes from the buffer pointed buf to the
 * buffer pointed dst.
 */

int writeBuf(u1 *dst, void *buf, int count);
/*
 * Read up to count bytes from the buffer pointed src to the
 * buffer pointed buf.
 */

/* 
 * Write number of byte count data to file descriptor
 */
int writeFD(int fd, u1 *buff, int count, FILE *file);


int readBuf(u1 *src, void *buf, int count);
/* 
 * Read number of bytes char source to int destination, 
 * with big endian form.
 */
int readBE(u1 *src, int *dst, int bytes);

/* 
 * Read number of byte count data from file descriptor
 */
int readFD(int fd, u1 *buff, int count, FILE *file);

#endif

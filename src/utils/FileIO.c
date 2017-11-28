#include "FileIO.h"

static void writeFile(u1 *buf, int counts, FILE *file)
{
	if (file != NULL) {
		fwrite(buf, 1, counts, file);
		fflush(file);
	}
}

/* 
 * Write up to count of elements from source array to char* 
 * destination with big endian format. Argument size means 
 * the size of every element in array. Size must be between 
 * 1 to 8.
 */
int writeArrBE(u1 *dst, u1 *arr, int size, int count)
{
	int i;
	u1 *ptr = dst;

	for (i=0; i<count; i++) {
		int element;
		memcpy(&element, arr+(i*size), size);
		ptr += writeBE(ptr, element, size);
	}
	return size * count;
}

/*
 * Write up to count bytes from the buffer pointed buf to the
 * buffer pointed dst.
 */
int writeBuf(u1 *dst, void *buf, int count)
{
	memcpy(dst, buf, count);

	return count;
}
/* 
 * Write unsigned long long int source to char* destination. Parameter 
 * byte means the size of the element to write from src. For example, 
 * src = 0x24, and bytes = 5, we have to write big endian 
 * format(00 00 00 00 24)hex to the destination. The return value 
 * will be the written size count in bytes.
 */
int writeBE(u1 *dst, u8 src, int bytes)
{
	int i;
	u8 bigEnd = 0;

	for (i=bytes-1; i>=0; i--) {
		bigEnd |= ((src & 0xFF) << (i<<3));
		src >>= 8;
	}
	return writeBuf(dst, &bigEnd, bytes);
}

/*
 * Read up to count bytes from the buffer pointed src to the
 * buffer pointed buf.
 */
int readBuf(u1 *src, void *buf, int count)
{
	memcpy(buf, src, count);

	return count;
}
/* 
 * Read Char source to int destination. Parameter bytes means
 * how many byte to read from src. For example, src = "1234",
 * and bytes = 2, we read and change BE to LE and save to dst.
 * The return value will be the read size count in bytes.
 */
int readBE(u1 *src, int *dst, int bytes)
{
	int i;

	*dst = 0;
	for (i=bytes-1; i>=0; i--) {
		*dst |= (*src << (i<<3));
		src++;
	}

	return bytes;
}

/* 
 * Write count byte data to the file descriptor from buff.
 */
int writeFD(int fd, u1 *buf, int count, FILE *file)
{
	int wCount;
	int left = count;
	u1 *ptr = buf;

	while (left > 0) {
		if ((wCount = write(fd, ptr, left)) <= 0) {
			if (wCount < 0 && errno == EINTR) { 
				/* write interrupted, try to write again */
				wCount = 0;
			} else {
				printf("%d\n", errno);
				/* error */
				return -1;
			}
		}
		ptr += wCount;
		left -= wCount;
	}
#if defined(DEBUG)
	if (file != NULL)
		writeFile(buf, count, file);
#endif
	return count;
}

/* 
 * Read count byte data from the file descriptor to buff.
 */
int readFD(int fd, u1 *buf, int count, FILE *file)
{
	int rCount;
	int left = count;
	u1 *ptr = buf;

	while (left > 0) {
		rCount = read(fd, ptr, left);
		if (rCount < 0) {
			/* read interrupted, try to read again */
			if (errno == EINTR)
				rCount = 0;
			else
				return -1;
		} else {
			/*  
			 * FIXME: TEMPORARY fix, make it more robust
			 */
#if 0
			if ((rCount < left) || rCount == 0) {
				//left -= rCount;
				//break;
			}
#endif
			ptr += rCount;
			left -= rCount;
		}
	}
	
#if defined(DEBUG)
	if (file != NULL)
		writeFile(buf, count - left, file);
#endif
	return (count - left);
}

#ifndef _BIT_OP_H_
#define _BIT_OP_H_

#include "../Common.h"

#define LEFT_ROTATE(_val, _num)	\
	(((_val) << _num) | (((unsigned int)(_val)) >> (32-_num)))

u8 reverseWord(u8 in, int size);

#endif

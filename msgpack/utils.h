// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Richard Palethorpe <rpalethorpe@suse.com>
 * Copyright (c) 2023 Andrea Cervesato <andrea.cervesato@suse.com>
 */

#ifndef MSGPACK_H
#define MSGPACK_H

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
 #define BIT_LEFT_SHIFT(x, pos) (x << pos)
 #define BIT_RIGHT_SHIFT(x, pos) (x >> pos)
#else
 #define BIT_LEFT_SHIFT(x, pos) (x >> pos)
 #define BIT_RIGHT_SHIFT(x, pos) (x << pos)
#endif

#include <stdint.h>
#include <string.h>

/* takes a number and convert it into a big-endian array */
static uint64_t mp_bytes_to_number(uint8_t *const bytes, const int len)
{
	uint64_t value = 0;

	switch (len)
	{
	case 1:
		value += (uint64_t)bytes[0];
		break;
	case 2:
		value += BIT_LEFT_SHIFT((uint64_t)bytes[0], 8);
		value += (uint64_t)bytes[1];
		break;
	case 4:
		value += BIT_LEFT_SHIFT((uint64_t)bytes[0], 24);
		value += BIT_LEFT_SHIFT((uint64_t)bytes[1], 16);
		value += BIT_LEFT_SHIFT((uint64_t)bytes[2], 8);
		value += (uint64_t)bytes[3];
		break;
	case 8:
		value += BIT_LEFT_SHIFT((uint64_t)bytes[0], 56);
		value += BIT_LEFT_SHIFT((uint64_t)bytes[1], 48);
		value += BIT_LEFT_SHIFT((uint64_t)bytes[2], 40);
		value += BIT_LEFT_SHIFT((uint64_t)bytes[3], 32);
		value += BIT_LEFT_SHIFT((uint64_t)bytes[4], 24);
		value += BIT_LEFT_SHIFT((uint64_t)bytes[5], 16);
		value += BIT_LEFT_SHIFT((uint64_t)bytes[6], 8);
		value += (uint64_t)bytes[7];
		break;
	default:
		break;
	}

	return value;
}

/* takes a big-endian array and convert it into a number */
static void mp_number_to_bytes(const uint64_t value, uint8_t *bytes, int *len)
{
	memset(bytes, 0, 8);

	if (value <= 0xff) {
		bytes[0] = (uint8_t)(value & 0xff);
		*len = 1;
	} else if (value <= 0xffff) {
		bytes[0] = (uint8_t)(BIT_RIGHT_SHIFT(value, 8) & 0xff);
		bytes[1] = (uint8_t)(value & 0xff);
		*len = 2;
	} else if (value <= 0xffffffff) {
		bytes[0] = (uint8_t)(BIT_RIGHT_SHIFT(value, 24) & 0xff);
		bytes[1] = (uint8_t)(BIT_RIGHT_SHIFT(value, 16) & 0xff);
		bytes[2] = (uint8_t)(BIT_RIGHT_SHIFT(value, 8) & 0xff);
		bytes[3] = (uint8_t)(value & 0xff);
		*len = 4;
	} else {
		bytes[0] = (uint8_t)(BIT_RIGHT_SHIFT(value, 56) & 0xff);
		bytes[1] = (uint8_t)(BIT_RIGHT_SHIFT(value, 48) & 0xff);
		bytes[2] = (uint8_t)(BIT_RIGHT_SHIFT(value, 40) & 0xff);
		bytes[3] = (uint8_t)(BIT_RIGHT_SHIFT(value, 32) & 0xff);
		bytes[4] = (uint8_t)(BIT_RIGHT_SHIFT(value, 24) & 0xff);
		bytes[5] = (uint8_t)(BIT_RIGHT_SHIFT(value, 16) & 0xff);
		bytes[6] = (uint8_t)(BIT_RIGHT_SHIFT(value, 8) & 0xff);
		bytes[7] = (uint8_t)(value & 0xff);
		*len = 8;
	}
}

#endif

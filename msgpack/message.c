// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Richard Palethorpe <rpalethorpe@suse.com>
 * Copyright (c) 2023 Andrea Cervesato <andrea.cervesato@suse.com>
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "message.h"
#include "utils.h"

void mp_message_init(struct mp_message *msg)
{
	assert(msg);

	msg->length = 0;
	msg->data = NULL;
}

void mp_message_destroy(struct mp_message *msg)
{
	assert(msg);

	if (msg->data) {
		free(msg->data);
		msg->data = NULL;
	}
}

int mp_message_type(struct mp_message *msg)
{
	assert(msg);
	assert(msg->data);

	int type = -1;

	switch (msg->data[0]) {
	case MP_FIXINT0 ... MP_FIXINT127:
	case MP_UINT8:
	case MP_UINT16:
	case MP_UINT32:
	case MP_UINT64:
		type = MP_NUMERIC;
		break;
	case MP_FIXSTR0 ... MP_FIXSTR31:
	case MP_STR8:
	case MP_STR16:
	case MP_STR32:
		type = MP_STRING;
		break;
	case MP_BIN8:
	case MP_BIN16:
	case MP_BIN32:
		type = MP_BINARY;
		break;
	default:
		break;
	}

	assert(type != -1);

	return type;
}

size_t mp_message_base_size(const uint8_t type)
{
	size_t base;

	switch (type) {
	case MP_FIXINT0 ... MP_FIXINT127:
		base = 1;
		break;
	case MP_BIN8:
	case MP_STR8:
	case MP_UINT8:
		base = 2;
		break;
	case MP_BIN16:
	case MP_STR16:
	case MP_UINT16:
		base = 3;
		break;
	case MP_BIN32:
	case MP_STR32:
	case MP_UINT32:
		base = 5;
		break;
	case MP_UINT64:
		base = 9;
		break;
	case MP_FIXSTR0 ... MP_FIXSTR31:
		base = type - MP_FIXSTR0 + 1;
		break;
	default:
		base = 0;
		break;
	}

	return base;
}

size_t mp_message_full_size(struct mp_message *msg)
{
	size_t size = 0;

	switch (msg->data[0]) {
	case MP_UINT8:
	case MP_UINT16:
	case MP_UINT32:
	case MP_UINT64:
	case MP_FIXSTR0 ... MP_FIXSTR31:
	case MP_FIXINT0 ... MP_FIXINT127:
		size += mp_message_base_size(msg->data[0]);
		break;
	case MP_BIN8:
	case MP_STR8:
		size += 2;
		size += (size_t)msg->data[1];
		break;
	case MP_BIN16:
	case MP_STR16:
		size += 3;
		size += (size_t)msg->data[1];
		size += (size_t)BIT_LEFT_SHIFT(msg->data[2], 8);
		break;
	case MP_BIN32:
	case MP_STR32:
		size += 5;
		size += (size_t)msg->data[1];
		size += (size_t)BIT_LEFT_SHIFT(msg->data[2], 8);
		size += (size_t)BIT_LEFT_SHIFT(msg->data[3], 16);
		size += (size_t)BIT_LEFT_SHIFT(msg->data[4], 24);
		break;
	default:
		size = 0;
		break;
	}

	return size;
}

void mp_message_uint(struct mp_message *msg, const uint64_t value)
{
	assert(msg);

	mp_message_init(msg);

	if (value <= 127) {
		msg->length = 1;
		msg->data = (uint8_t *) malloc(1);
		msg->data[0] = (uint8_t) value;
		return;
	}

	uint8_t type;
	uint8_t data[8];
	int len;

	mp_number_to_bytes(value, data, &len);

	switch (len) {
	case 1:
		type = MP_UINT8;
		break;
	case 2:
		type = MP_UINT16;
		break;
	case 4:
		type = MP_UINT32;
		break;
	default:
		type = MP_UINT64;
		break;
	}

	msg->length = 1 + len;
	msg->data = (uint8_t *) malloc(msg->length);
	msg->data[0] = type;

	for (int i = 0; i < len; i++)
		msg->data[1 + i] = data[i];
}

uint64_t mp_message_read_uint(struct mp_message *msg)
{
	assert(msg);
	assert(msg->data);

	size_t start = mp_message_base_size(msg->data[0]);
	assert(start > 0);

	uint64_t value = start > 1 ?
		mp_bytes_to_number(msg->data + 1, start - 1) :
		(uint64_t) msg->data[0];

	return value;
}

void mp_message_str(struct mp_message *msg, const char *const str)
{
	assert(msg);
	assert(str);

	uint8_t type;
	uint8_t lendata[8];
	int lensize = 0;

	mp_message_init(msg);

	size_t datasize = strlen(str);
	assert(datasize <= 0xffffffff);

	if (datasize <= 32) {
		type = MP_FIXSTR0 + datasize;
	} else {
		mp_number_to_bytes(datasize, lendata, &lensize);

		switch(lensize) {
		case 1:
			type = MP_STR8;
			break;
		case 2:
			type = MP_STR16;
			break;
		default:
			type = MP_STR32;
			break;
		}
	}

	msg->length = 1 + lensize + datasize;

	msg->data = (uint8_t *) malloc(msg->length);
	memset(msg->data, 0, msg->length);

	msg->data[0] = type;

	if (lensize > 0)
		memcpy(msg->data + 1, lendata, lensize);

	memcpy(msg->data + 1 + lensize, str, datasize);
}

char *mp_message_read_str(struct mp_message *msg, size_t *size)
{
	assert(msg);
	assert(msg->data);

	if (msg->data[0] >= MP_FIXSTR0 && msg->data[0] <= MP_FIXSTR31) {
		*size = msg->data[0] - MP_FIXSTR0;
		return msg->data + 1;
	}

	size_t start = mp_message_base_size(msg->data[0]);
	assert(start > 0);

	*size = msg->length - start;

	return msg->data + start;
}

void mp_message_bin(
	struct mp_message *msg,
	uint8_t *const data,
	const size_t size)
{
	assert(msg);
	assert(data);
	assert(size > 0 && size <= 0xffffffff);

	uint8_t type;
	uint8_t length[8];
	int lensize;

	mp_message_init(msg);
	mp_number_to_bytes(size, length, &lensize);

	switch(lensize) {
	case 1:
		type = MP_BIN8;
		break;
	case 2:
		type = MP_BIN16;
		break;
	default:
		type = MP_BIN32;
		break;
	}

	msg->length = 1 + lensize + size;

	msg->data = (uint8_t *) malloc(msg->length);
	memset(msg->data, 0, msg->length);

	msg->data[0] = type;
	memcpy(msg->data + 1, length, lensize);
	memcpy(msg->data + 1 + lensize, data, size);
}

uint8_t *mp_message_read_bin(struct mp_message *msg, size_t *size)
{
	assert(msg);
	assert(msg->data);
	assert(size);

	size_t start = mp_message_base_size(msg->data[0]);
	assert(start > 0);

	*size = msg->length - start;

	return msg->data + start;
}

// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Richard Palethorpe <rpalethorpe@suse.com>
 * Copyright (c) 2023 Andrea Cervesato <andrea.cervesato@suse.com>
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "message.h"
#include "utils.h"

static void mp_message_alloc(struct mp_message *msg, const size_t bytes)
{
	msg->length = bytes;
	msg->data = (uint8_t *) realloc(msg->data, msg->length);
}

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
	case MP_FIXARRAY0 ... MP_FIXARRAY15:
	case MP_ARRAY16:
	case MP_ARRAY32:
		type = MP_ARRAY;
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
	case MP_FIXARRAY0 ... MP_FIXARRAY15:
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
	case MP_ARRAY16:
		base = 3;
		break;
	case MP_BIN32:
	case MP_STR32:
	case MP_UINT32:
	case MP_ARRAY32:
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
	case MP_FIXARRAY0 ... MP_FIXARRAY15:
	case MP_ARRAY16 ... MP_ARRAY32:
		size += mp_message_base_size(msg->data[0]);
		break;
	case MP_BIN8:
	case MP_STR8:
		size += 2;
		size += mp_read_number(msg->data + 1, 1);
		break;
	case MP_BIN16:
	case MP_STR16:
		size += 3;
		size += mp_read_number(msg->data + 1, 2);
		break;
	case MP_BIN32:
	case MP_STR32:
		size += 5;
		size += mp_read_number(msg->data + 1, 4);
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
		mp_message_alloc(msg, 1);
		msg->data[0] = (uint8_t) (value & 0xff);
		return;
	}

	int len = mp_read_number_bytes(value);
	uint8_t type;

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

	mp_message_alloc(msg, 1 + len);

	msg->data[0] = type;
	mp_write_number(value, msg->data + 1, len);
}

uint64_t mp_message_read_uint(struct mp_message *msg)
{
	assert(msg);
	assert(msg->data);

	size_t size = mp_message_full_size(msg);
	assert(size > 0);

	if (size == 1)
		return (uint64_t) msg->data[0];

	uint64_t value = mp_read_number(msg->data + 1, size - 1);

	return value;
}

void mp_message_str(struct mp_message *msg, const char *const str)
{
	assert(msg);
	assert(str);

	mp_message_init(msg);

	size_t datasize = strlen(str);
	assert(datasize <= 0xffffffff);

	int lensize = mp_read_number_bytes(datasize);
	uint8_t type;

	if (datasize <= 32) {
		type = MP_FIXSTR0 + datasize;
		lensize = 0;
	} else {
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

	mp_message_alloc(msg, 1 + lensize + datasize);

	msg->data[0] = type;
	if (lensize > 0)
		mp_write_number(datasize, msg->data + 1, lensize);

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

	mp_message_init(msg);

	int lensize = mp_read_number_bytes(size);
	uint8_t type;

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

	mp_message_alloc(msg, 1 + lensize + size);

	msg->data[0] = type;
	mp_write_number((uint64_t)size, msg->data + 1, lensize);
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

void mp_message_array(struct mp_message *msg, const size_t length)
{
	assert(msg);
	assert(length >= 1);
	assert(length <= 0xffffffff);

	mp_message_init(msg);

	if (length <= MP_FIXARRAY15) {
		mp_message_alloc(msg, 1);
		msg->data[0] = MP_FIXARRAY0 | length;
		return;
	}

	int len;
	uint8_t type;

	if (length <= 0xffff) {
		len = 2;
		type = MP_ARRAY16;
	} else {
		len = 4;
		type = MP_ARRAY32;
	}

	mp_message_alloc(msg, 1 + len);

	msg->data[0] = type;
	mp_write_number(length, msg->data + 1, len);
}

size_t mp_message_read_array_length(struct mp_message *msg)
{
	assert(msg);
	assert(msg->data);

	if (msg->data[0] >= MP_FIXARRAY0 && msg->data[0] <= MP_FIXARRAY15)
		return (size_t)(msg->data[0] - MP_FIXARRAY0);

	int bytes = msg->data[0] == MP_ARRAY16 ? 2 : 4;
	uint64_t length = mp_read_number(msg->data + 1, bytes);

	return length;
}

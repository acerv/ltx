// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Andrea Cervesato <andrea.cervesato@suse.com>
 */

#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include "unpack.h"
#include "utils.h"

START_TEST(test_unpack_uint8)
{
	struct mp_message msg;
	struct mp_unpacker unpacker;

	mp_message_init(&msg);
	mp_unpacker_init(&unpacker);
	mp_unpacker_reserve(&unpacker, &msg);

	uint8_t data[] = {MP_UINT8, 0x10};
	size_t offset = mp_unpacker_feed(&unpacker, data, 2);

	ck_assert_int_eq(mp_unpacker_status(&unpacker), MP_UNPACKER_SUCCESS);
	ck_assert_uint_eq(offset, 2);
	ck_assert_mem_eq(msg.data, data, 2);
}
END_TEST

START_TEST(test_unpack_uint16)
{
	struct mp_message msg;
	struct mp_unpacker unpacker;

	mp_message_init(&msg);
	mp_unpacker_init(&unpacker);
	mp_unpacker_reserve(&unpacker, &msg);

	uint8_t data[] = {MP_UINT16, 0x10, 0xc0};
	size_t offset = mp_unpacker_feed(&unpacker, data, 3);

	ck_assert_int_eq(mp_unpacker_status(&unpacker), MP_UNPACKER_SUCCESS);
	ck_assert_uint_eq(offset, 3);
	ck_assert_mem_eq(msg.data, data, 3);

	mp_message_destroy(&msg);
}
END_TEST

START_TEST(test_unpack_uint32)
{
	struct mp_message msg;
	struct mp_unpacker unpacker;

	mp_message_init(&msg);
	mp_unpacker_init(&unpacker);
	mp_unpacker_reserve(&unpacker, &msg);

	uint8_t data[] = {MP_UINT32, 0x10, 0xc0, 0x20, 0xc1};
	size_t offset = mp_unpacker_feed(&unpacker, data, 5);

	ck_assert_int_eq(mp_unpacker_status(&unpacker), MP_UNPACKER_SUCCESS);
	ck_assert_uint_eq(offset, 5);
	ck_assert_mem_eq(msg.data, data, 5);

	mp_message_destroy(&msg);
}
END_TEST

START_TEST(test_unpack_uint64)
{
	struct mp_message msg;
	struct mp_unpacker unpacker;

	mp_message_init(&msg);
	mp_unpacker_init(&unpacker);
	mp_unpacker_reserve(&unpacker, &msg);

	uint8_t data[] = {
		MP_UINT64,
		0x10, 0xc0, 0x20, 0xc1,
		0x30, 0xc2, 0x40, 0xc3
	};
	size_t offset = mp_unpacker_feed(&unpacker, data, 9);

	ck_assert_int_eq(mp_unpacker_status(&unpacker), MP_UNPACKER_SUCCESS);
	ck_assert_uint_eq(offset, 9);
	ck_assert_mem_eq(msg.data, data, 9);

	mp_message_destroy(&msg);
}
END_TEST

START_TEST(test_unpack_split_uint)
{
	size_t offset;
	struct mp_message msg;
	struct mp_unpacker unpacker;

	mp_message_init(&msg);
	mp_unpacker_init(&unpacker);
	mp_unpacker_reserve(&unpacker, &msg);

	uint8_t data[] = {
		MP_UINT64,
		0x10, 0xc0, 0x20, 0xc1,
		0x30, 0xc2, 0x40, 0xc3,
	};

	/* unpack first 5 bytes */
	offset = mp_unpacker_feed(&unpacker, data, 5);

	ck_assert_uint_eq(offset, 5);
	ck_assert_int_eq(mp_unpacker_status(&unpacker), MP_UNPACKER_NEED_DATA);
	ck_assert_uint_eq(msg.data[0], MP_UINT64);
	ck_assert_uint_eq(msg.length, 9);
	ck_assert_mem_eq(msg.data, data, 4);

	/* unpack last 4 bytes */
	offset = mp_unpacker_feed(&unpacker, data + 5, 4);

	ck_assert_int_eq(mp_unpacker_status(&unpacker), MP_UNPACKER_SUCCESS);
	ck_assert_uint_eq(offset, 4);
	ck_assert_uint_eq(msg.data[0], MP_UINT64);
	ck_assert_uint_eq(msg.length, 9);
	ck_assert_mem_eq(msg.data, data, 9);

	mp_message_destroy(&msg);
}
END_TEST

START_TEST(test_unpack_fixstr)
{
	size_t offset;
	struct mp_message msg;
	struct mp_unpacker unpacker;

	mp_message_init(&msg);
	mp_unpacker_init(&unpacker);
	mp_unpacker_reserve(&unpacker, &msg);

	uint8_t type = MP_FIXSTR0 + 5;
	uint8_t data[] = {
		type,
		'c', 'i', 'a', 'o', '\0',
	};

	offset = mp_unpacker_feed(&unpacker, data, 6);

	ck_assert_int_eq(mp_unpacker_status(&unpacker), MP_UNPACKER_SUCCESS);
	ck_assert_uint_eq(offset, 6);
	ck_assert_uint_eq(msg.data[0], type);
	ck_assert_uint_eq(msg.length, 6);
	ck_assert_mem_eq(msg.data, data, 6);

	mp_message_destroy(&msg);
}
END_TEST

static void test_unpack_data(const uint8_t type)
{
	const size_t msg_size = 5;
	uint8_t msg_data[] = {'x', 'x', 'x', 'x', '\0'};
	uint8_t *data;

	size_t offset;
	int lenbytes;
	int totlen;
	uint8_t length[8];
	struct mp_message msg;
	struct mp_unpacker unpacker;

	mp_message_init(&msg);
	mp_unpacker_init(&unpacker);
	mp_unpacker_reserve(&unpacker, &msg);
	mp_number_to_bytes(msg_size, length, &lenbytes);

	switch (type) {
	case MP_STR8:
	case MP_BIN8:
		lenbytes = 1;
		break;
	case MP_STR16:
	case MP_BIN16:
		lenbytes = 2;
		break;
	case MP_STR32:
	case MP_BIN32:
		lenbytes = 4;
		break;
	default:
		break;
	}

	/* type | length | data */
	totlen = 1 + lenbytes + msg_size;
	data = (uint8_t *) malloc(totlen);

	data[0] = type;
	memcpy(data + 1, length, lenbytes);
	memcpy(data + 1 + lenbytes, msg_data, msg_size);

	/* unpack data */
	offset = mp_unpacker_feed(&unpacker, data, totlen);

	ck_assert_uint_eq(offset, totlen);
	ck_assert_int_eq(mp_unpacker_status(&unpacker), MP_UNPACKER_SUCCESS);
	ck_assert_uint_eq(msg.data[0], type);
	ck_assert_uint_eq(msg.length, totlen);
	ck_assert_mem_eq(msg.data, data, totlen);

	mp_message_destroy(&msg);
}

START_TEST(test_unpack_str8)
{
	test_unpack_data(MP_STR8);
}
END_TEST

START_TEST(test_unpack_str16)
{
	test_unpack_data(MP_STR16);
}
END_TEST

START_TEST(test_unpack_str32)
{
	test_unpack_data(MP_STR32);
}
END_TEST

START_TEST(test_unpack_split_str)
{
	struct mp_message msg;
	struct mp_unpacker unpacker;

	mp_message_init(&msg);
	mp_unpacker_init(&unpacker);
	mp_unpacker_reserve(&unpacker, &msg);

	size_t size = 10;
	uint8_t data[] = {
		MP_STR32,
		0x5, 0x00, 0x00, 0x00,
		'c', 'i', 'a', 'o', '\0'
	};

	size_t offset = 0;

	do {
		offset += mp_unpacker_feed(&unpacker, data + offset, 2);
	} while (offset < size);

	ck_assert_uint_eq(offset, size);
	ck_assert_int_eq(mp_unpacker_status(&unpacker), MP_UNPACKER_SUCCESS);
	ck_assert_uint_eq(msg.data[0], MP_STR32);
	ck_assert_uint_eq(msg.length, size);
	ck_assert_mem_eq(msg.data, data, size);

	mp_message_destroy(&msg);
}
END_TEST

START_TEST(test_unpack_bin8)
{
	test_unpack_data(MP_BIN8);
}
END_TEST

START_TEST(test_unpack_bin16)
{
	test_unpack_data(MP_BIN16);
}
END_TEST

START_TEST(test_unpack_bin32)
{
	test_unpack_data(MP_BIN32);
}
END_TEST

START_TEST(test_unpack_multiple)
{
	struct mp_message msg;
	struct mp_unpacker unpacker;

	mp_message_init(&msg);
	mp_unpacker_init(&unpacker);
	mp_unpacker_reserve(&unpacker, &msg);

	int size = 16;
	uint8_t data[] = {
		MP_FIXSTR0 + 5,
		'c', 'i', 'a', 'o', '\0',
		MP_BIN8,
		0x4,
		'd', 'a', 't', 'a',
		MP_UINT64,
		0x01, 0x02, 0xff
	};

	size_t offset = 0;
	int num = 1;

	do {
		offset += mp_unpacker_feed(&unpacker, data + offset, 1);

		if (mp_unpacker_status(&unpacker) == MP_UNPACKER_SUCCESS) {
			switch(num) {
			case 1:
				ck_assert_uint_eq(msg.length, 6);
				ck_assert_mem_eq(msg.data, ((uint8_t []) {
					MP_FIXSTR0 + 5,
					'c', 'i', 'a', 'o', '\0',
				}), 6);
				break;
			case 2:
				ck_assert_uint_eq(msg.length, 6);
				ck_assert_mem_eq(msg.data, ((uint8_t []) {
					MP_BIN8,
					0x4,
					'd', 'a', 't', 'a',
				}), 6);
				break;
			case 3:
				ck_assert_uint_eq(msg.length, 4);
				ck_assert_mem_eq(msg.data, ((uint8_t []) {
					MP_UINT64,
					0x01, 0x02, 0xff
				}), 4);
				break;
			}
			num++;
		}
	} while (offset < size);

	ck_assert_uint_eq(offset, size);
	ck_assert_int_eq(num, 3);

	mp_message_destroy(&msg);
}
END_TEST

Suite *msgpack_suite(void)
{
	Suite *s;
	TCase *tc;

	s = suite_create("unpack");

	tc = tcase_create("test_unpack_uint8");
	tcase_add_test(tc, test_unpack_uint8);
	suite_add_tcase(s, tc);

	tc = tcase_create("test_unpack_uint16");
	tcase_add_test(tc, test_unpack_uint16);
	suite_add_tcase(s, tc);

	tc = tcase_create("test_unpack_uint32");
	tcase_add_test(tc, test_unpack_uint32);
	suite_add_tcase(s, tc);

	tc = tcase_create("test_unpack_uint64");
	tcase_add_test(tc, test_unpack_uint64);
	suite_add_tcase(s, tc);

	tc = tcase_create("test_unpack_split_uint");
	tcase_add_test(tc, test_unpack_split_uint);
	suite_add_tcase(s, tc);

	tc = tcase_create("test_unpack_fixstr");
	tcase_add_test(tc, test_unpack_fixstr);
	suite_add_tcase(s, tc);

	tc = tcase_create("test_unpack_str8");
	tcase_add_test(tc, test_unpack_str8);
	suite_add_tcase(s, tc);

	tc = tcase_create("test_unpack_str16");
	tcase_add_test(tc, test_unpack_str16);
	suite_add_tcase(s, tc);

	tc = tcase_create("test_unpack_str32");
	tcase_add_test(tc, test_unpack_str32);
	suite_add_tcase(s, tc);

	tc = tcase_create("test_unpack_split_str");
	tcase_add_test(tc, test_unpack_split_str);
	suite_add_tcase(s, tc);

	tc = tcase_create("test_unpack_bin8");
	tcase_add_test(tc, test_unpack_bin8);
	suite_add_tcase(s, tc);

	tc = tcase_create("test_unpack_bin16");
	tcase_add_test(tc, test_unpack_bin16);
	suite_add_tcase(s, tc);

	tc = tcase_create("test_unpack_bin32");
	tcase_add_test(tc, test_unpack_bin32);
	suite_add_tcase(s, tc);

	tc = tcase_create("test_unpack_multiple");
	tcase_add_test(tc, test_unpack_multiple);
	suite_add_tcase(s, tc);

	return s;
}

int main(void)
{
	int number_failed;
	Suite *s;
	SRunner *sr;

	s = msgpack_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return number_failed == 0;
}

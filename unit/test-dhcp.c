/*
 * Embedded Linux library
 * Copyright (C) 2018  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <linux/types.h>
#include <netinet/ip.h>
#include <linux/if_arp.h>
#include <errno.h>

#include <ell/ell.h>
#include "ell/dhcp-private.h"

static bool verbose = false;
static uint8_t client_packet[1024];
static size_t client_packet_len;
static uint8_t server_packet[1024];
static size_t server_packet_len;

static void test_request_option(const void *data)
{
	struct l_dhcp_client *dhcp;

	dhcp = l_dhcp_client_new(0);
	assert(dhcp);

	assert(!l_dhcp_client_add_request_option(NULL, 0));

	assert(l_dhcp_client_add_request_option(dhcp,
						L_DHCP_OPTION_SUBNET_MASK));
	assert(l_dhcp_client_add_request_option(dhcp,
						L_DHCP_OPTION_ROUTER));
	assert(l_dhcp_client_add_request_option(dhcp,
						L_DHCP_OPTION_HOST_NAME));
	assert(l_dhcp_client_add_request_option(dhcp,
						L_DHCP_OPTION_DOMAIN_NAME));
	assert(l_dhcp_client_add_request_option(dhcp,
					L_DHCP_OPTION_DOMAIN_NAME_SERVER));
	assert(l_dhcp_client_add_request_option(dhcp,
					L_DHCP_OPTION_NTP_SERVERS));
	assert(!l_dhcp_client_add_request_option(dhcp, 0));
	assert(!l_dhcp_client_add_request_option(dhcp, 255));
	assert(!l_dhcp_client_add_request_option(dhcp, 52));
	assert(!l_dhcp_client_add_request_option(dhcp, 53));
	assert(!l_dhcp_client_add_request_option(dhcp, 55));

	assert(l_dhcp_client_add_request_option(dhcp, 33));
	assert(l_dhcp_client_add_request_option(dhcp, 44));

	l_dhcp_client_destroy(dhcp);
}

static void test_invalid_message_length(const void *data)
{
	struct dhcp_message message;
	struct dhcp_message_iter iter;

	memset(&message, 0, sizeof(message));
	assert(!_dhcp_message_iter_init(&iter, NULL, 0));
	assert(!_dhcp_message_iter_init(&iter, &message, sizeof(message)));
}

static void test_cookie(const void *data)
{
	struct dhcp_message *message;
	size_t len = sizeof(struct dhcp_message);
	uint8_t *opt;
	struct dhcp_message_iter iter;

	message = (struct dhcp_message *) l_new(uint8_t, len);
	opt = (uint8_t *)(&message->magic);
	opt[0] = 0xff;

	assert(!_dhcp_message_iter_init(&iter, message, len));

	opt[0] = 99;
	opt[1] = 130;
	opt[2] = 83;
	opt[3] = 99;

	assert(_dhcp_message_iter_init(&iter, message, len));
	assert(!_dhcp_message_iter_next(&iter, NULL, NULL, NULL));

	l_free(message);
}

struct option_test {
	uint8_t sname[64];
	int snamelen;
	uint8_t file[128];
	int filelen;
	uint8_t options[128];
	int len;
};

static const struct option_test option_test_1 = {
	.options = { 42, 5, 65, 66, 67, 68, 69 },
	.len = 7,
};

static const struct option_test option_test_2 = {
	.options = { 42, 5, 65, 66, 67, 68, 69, 0, 0, 53, 1, 5 },
	.len = 12,
};

static const struct option_test option_test_3 = {
	.options = { 8, 255, 70, 71, 72 },
	.len = 5,
};

static const struct option_test option_test_4 = {
	.options = { 0x35, 0x01, 0x05, 0x36, 0x04, 0x01, 0x00, 0xa8,
			0xc0, 0x33, 0x04, 0x00, 0x01, 0x51, 0x80, 0x01,
			0x04, 0xff, 0xff, 0xff, 0x00, 0x03, 0x04, 0xc0,
			0xa8, 0x00, 0x01, 0x06, 0x04, 0xc0, 0xa8, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
	.len = 40,
};

static const struct option_test option_test_5 = {
	.options = { 53, 1, 2, 42, 3, 0, 0, 0 },
	.len =  8,
};

static const struct option_test option_test_6 = {
	.options = { 42, 2, 1, 2, 44 },
	.len = 5,
};

static const struct option_test option_test_7 = {
	.file = { 222, 3, 1, 2, 3, 53, 1, 6 },
	.filelen = 8,
	.options = { 52, 0x1, 0x1 },
	.len = 3,
};

static const struct option_test option_test_8 = {
	.sname = { 1, 4, 1, 2, 3, 4, 53, 1, 5 },
	.snamelen = 9,
	.file = { 222, 3, 1, 2, 3 },
	.filelen = 5,
	.options = { 52, 0x1, 0x3 },
	.len = 3,
};

static struct dhcp_message *create_message(const struct option_test *test,
						size_t *out_len)
{
	struct dhcp_message *message;
	size_t len = sizeof(struct dhcp_message) + test->len;
	uint8_t *opt;

	message = (struct dhcp_message *) l_new(uint8_t, len);
	opt = (uint8_t *)(&message->magic);

	opt[0] = 99;
	opt[1] = 130;
	opt[2] = 83;
	opt[3] = 99;

	if (test->len)
		memcpy(&opt[4], test->options, test->len);

	if (test->filelen <= 128)
		memcpy(&message->file, test->file, test->filelen);

	if (test->snamelen <= 64)
		memcpy(&message->sname, test->sname, test->snamelen);

	if (out_len)
		*out_len = len;

	return message;
}

static void test_option_1(const void *data)
{
	const struct option_test *test = data;
	struct dhcp_message *message;
	struct dhcp_message_iter iter;
	size_t len;
	uint8_t t,l;

	message = create_message(test, &len);

	assert(_dhcp_message_iter_init(&iter, message, len));
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 42);
	assert(l == 5);
	assert(!_dhcp_message_iter_next(&iter, &t, &l, NULL));
	l_free(message);
}

static void test_option_2(const void *data)
{
	const struct option_test *test = data;
	struct dhcp_message *message;
	struct dhcp_message_iter iter;
	size_t len;
	uint8_t t,l;

	message = create_message(test, &len);

	assert(_dhcp_message_iter_init(&iter, message, len));
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 42);
	assert(l == 5);
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 53);
	assert(l == 1);
	assert(!_dhcp_message_iter_next(&iter, &t, &l, NULL));
	l_free(message);
}

static void test_option_3(const void *data)
{
	const struct option_test *test = data;
	struct dhcp_message *message;
	struct dhcp_message_iter iter;
	size_t len;

	message = create_message(test, &len);

	assert(_dhcp_message_iter_init(&iter, message, len));
	assert(!_dhcp_message_iter_next(&iter, NULL, NULL, NULL));
	l_free(message);
}

static void test_option_4(const void *data)
{
	const struct option_test *test = data;
	struct dhcp_message *message;
	struct dhcp_message_iter iter;
	size_t len;
	uint8_t t,l;

	message = create_message(test, &len);

	assert(_dhcp_message_iter_init(&iter, message, len));
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 0x35);
	assert(l == 1);
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 0x36);
	assert(l == 4);
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 0x33);
	assert(l == 4);
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 0x1);
	assert(l == 4);
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 0x3);
	assert(l == 4);
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 0x6);
	assert(l == 4);
	assert(!_dhcp_message_iter_next(&iter, &t, &l, NULL));
	l_free(message);
}

static void test_option_5(const void *data)
{
	const struct option_test *test = data;
	struct dhcp_message *message;
	struct dhcp_message_iter iter;
	size_t len;
	uint8_t t,l;

	message = create_message(test, &len);

	assert(_dhcp_message_iter_init(&iter, message, len));
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 53);
	assert(l == 1);
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 42);
	assert(l == 3);
	assert(!_dhcp_message_iter_next(&iter, &t, &l, NULL));
	l_free(message);
}

static void test_option_6(const void *data)
{
	const struct option_test *test = data;
	struct dhcp_message *message;
	struct dhcp_message_iter iter;
	size_t len;
	uint8_t t,l;

	message = create_message(test, &len);

	assert(_dhcp_message_iter_init(&iter, message, len));
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 42);
	assert(l == 2);
	assert(!_dhcp_message_iter_next(&iter, NULL, NULL, NULL));
	l_free(message);
}

static void test_option_7(const void *data)
{
	const struct option_test *test = data;
	struct dhcp_message *message;
	struct dhcp_message_iter iter;
	size_t len;
	uint8_t t,l;

	message = create_message(test, &len);

	assert(_dhcp_message_iter_init(&iter, message, len));
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 222);
	assert(l == 3);
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 53);
	assert(l == 1);
	assert(!_dhcp_message_iter_next(&iter, NULL, NULL, NULL));
	l_free(message);
}

static void test_option_8(const void *data)
{
	const struct option_test *test = data;
	struct dhcp_message *message;
	struct dhcp_message_iter iter;
	size_t len;
	uint8_t t, l;

	message = create_message(test, &len);

	assert(_dhcp_message_iter_init(&iter, message, len));
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 222);
	assert(l == 3);
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 1);
	assert(l == 4);
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 53);
	assert(l == 1);
	assert(!_dhcp_message_iter_next(&iter, NULL, NULL, NULL));
	l_free(message);
}

static void test_option_set(const void *data)
{
	struct dhcp_message_builder builder;
	struct dhcp_message *message;
	size_t outlen;
	uint8_t *msg_out;
	unsigned int i;
	static uint8_t result[sizeof(struct dhcp_message) + 64];
	static uint8_t options[64] = {
			160, 2, 0x11, 0x12,
			0,
			31, 8, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
			0,
			55, 3, 0x51, 0x52, 0x53,
			17, 7, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
			255
	};

	message = (struct dhcp_message *)result;

	/* test a few failure conditions */
	assert(!_dhcp_message_builder_init(NULL, NULL, 0, 0));
	assert(!_dhcp_message_builder_init(&builder, message, 0, 0));

	_dhcp_message_builder_init(&builder, message, sizeof(result),
					DHCP_MESSAGE_TYPE_DISCOVER);
	_dhcp_message_builder_append(&builder, 160, 2, options + 2);
	_dhcp_message_builder_append(&builder, 0, 0, NULL);
	_dhcp_message_builder_append(&builder, 31, 8, options + 7);
	_dhcp_message_builder_append(&builder, 0, 0, NULL);
	_dhcp_message_builder_append(&builder, 55, 3, options + 18);
	_dhcp_message_builder_append(&builder, 17, 7, options + 23);
	msg_out = _dhcp_message_builder_finalize(&builder, &outlen);

	/*
	 * The builde APIs automatically append the type passed in during init
	 * so we can skip over that in order to test the expected static data
	 */

	msg_out += sizeof(struct dhcp_message) + 3;

	for (i = 0; i < outlen - sizeof(struct dhcp_message); i++) {
		if (msg_out[i] != options[i]) {
			if (verbose) {
				l_info("byte[%d] did not match 0x%02x 0x%02x",
					i, msg_out[i], options[i]);
			}

			assert(false);
		}
	}
}

static void test_checksum(const void *data)
{
	static const uint8_t buf[20] = {
		0x45, 0x00, 0x02, 0x40, 0x00, 0x00, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0xff, 0xff
	};

	struct iovec iov[2];

	assert(_dhcp_checksum(&buf, 20) == L_BE16_TO_CPU(0x78ae));

	iov[0].iov_base = (void *) buf;
	iov[0].iov_len = 8;
	iov[1].iov_base = (void *) buf + 8;
	iov[1].iov_len = 12;

	assert(_dhcp_checksumv(iov, 2) == L_BE16_TO_CPU(0x78ae));
}

static const uint8_t discover_data_1[] = {
	0x01, 0x01, 0x06, 0x00, 0x4d, 0x7c, 0x67, 0xc6, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, 0x53, 0x63,
	0x35, 0x01, 0x01, 0x39, 0x02, 0x02, 0x40, 0x37, 0x06, 0x03, 0x2a, 0x0f,
	0x06, 0x01, 0x0c, 0x0c, 0x0a, 0x3c, 0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61,
	0x6d, 0x65, 0x3e, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t offer_data_1[] = {
	0x02, 0x01, 0x06, 0x00, 0x4d, 0x7c, 0x67, 0xc6, 0x00, 0x00, 0x80, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0xf9, 0xc0, 0xa8, 0x01, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, 0x53, 0x63,
	0x35, 0x01, 0x02, 0x36, 0x04, 0xc0, 0xa8, 0x01, 0x01, 0x33, 0x04, 0x00,
	0x01, 0x51, 0x80, 0x3a, 0x04, 0x00, 0x00, 0xa8, 0xc0, 0x3b, 0x04, 0x00,
	0x01, 0x27, 0x50, 0x01, 0x04, 0xff, 0xff, 0xff, 0x00, 0x1c, 0x04, 0xc0,
	0xa8, 0x01, 0xff, 0x06, 0x04, 0xc0, 0xa8, 0x01, 0x01, 0x03, 0x04, 0xc0,
	0xa8, 0x01, 0x01, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t request_data_1[] = {
	0x01, 0x01, 0x06, 0x00, 0x4d, 0x7c, 0x67, 0xc6, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, 0x53, 0x63,
	0x35, 0x01, 0x03, 0x32, 0x04, 0xc0, 0xa8, 0x01, 0xf9, 0x36, 0x04, 0xc0,
	0xa8, 0x01, 0x01, 0x39, 0x02, 0x02, 0x40, 0x37, 0x06, 0x03, 0x2a, 0x0f,
	0x06, 0x01, 0x0c, 0x0c, 0x0a, 0x3c, 0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61,
	0x6d, 0x65, 0x3e, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t ack_data_1[] = {
	0x02, 0x01, 0x06, 0x00, 0x4d, 0x7c, 0x67, 0xc6, 0x00, 0x00, 0x80, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0xf9, 0xc0, 0xa8, 0x01, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, 0x53, 0x63,
	0x35, 0x01, 0x05, 0x36, 0x04, 0xc0, 0xa8, 0x01, 0x01, 0x33, 0x04, 0x00,
	0x01, 0x51, 0x80, 0x3a, 0x04, 0x00, 0x00, 0xa8, 0xc0, 0x3b, 0x04, 0x00,
	0x01, 0x27, 0x50, 0x01, 0x04, 0xff, 0xff, 0xff, 0x00, 0x1c, 0x04, 0xc0,
	0xa8, 0x01, 0xff, 0x06, 0x04, 0xc0, 0xa8, 0x01, 0x01, 0x03, 0x04, 0xc0,
	0xa8, 0x01, 0x01, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

bool event_handler_called = false;

static int dhcp_message_prl_equal(const uint8_t *haystack,
					uint8_t len, const uint8_t *prl)
{
	unsigned int i, j;
	uint8_t needle;

	for (i = 0; i < len; i++) {
		needle = prl[i];

		for (j = 0; j < len; j++)
			if (haystack[j] == needle)
				break;

		if (j == len)
			return false;
	}

	return true;
}

static int dhcp_message_has_option(struct dhcp_message_iter *iter,
					uint8_t type, uint8_t len,
					const uint8_t *data)
{
	uint8_t t,l;
	const void *v;

	while (_dhcp_message_iter_next(iter, &t, &l, &v)) {
		if (t != type)
			continue;

		if (l != len)
			return -EMSGSIZE;

		if (type == 55)
			return dhcp_message_prl_equal(v, len, data);

		if (memcmp(data, v, len))
			return -EINVAL;

		return 0;
	}

	return -ENOENT;
}

static bool dhcp_message_compare(const uint8_t *expected, size_t expected_len,
				const uint8_t *obtained, size_t obtained_len)
{
	struct dhcp_message *e = (struct dhcp_message *) expected;
	struct dhcp_message *o = (struct dhcp_message *) obtained;
	struct dhcp_message_iter ei;
	bool r = true;
	uint8_t t, l;
	const void *v;

	assert(e->op == o->op);
	assert(e->htype == o->htype);
	assert(e->hlen == o->hlen);
	assert(e->hops == o->hops);

	/* Ignore xid & secs */

	assert(e->flags == o->flags);
	assert(e->ciaddr == o->ciaddr);
	assert(e->yiaddr == o->yiaddr);
	assert(e->giaddr == o->giaddr);
	assert(!memcmp(e->chaddr, o->chaddr, sizeof(e->chaddr)));

	assert(_dhcp_message_iter_init(&ei, e, expected_len));

	while (_dhcp_message_iter_next(&ei, &t, &l, &v)) {
		struct dhcp_message_iter oi;
		int err;

		assert(_dhcp_message_iter_init(&oi, o, obtained_len));
		err = dhcp_message_has_option(&oi, t, l, v);

		if (err >= 0)
			continue;

		r = false;
		switch (err) {
		case -EINVAL:
			l_info("Option %s(%hhu) payload doesn't match",
				_dhcp_option_to_string(t), t);
			break;
		case -EMSGSIZE:
			l_info("Option %s(%hhu) length doesn't match",
				_dhcp_option_to_string(t), t);
			break;
		case -ENOENT:
			l_info("Option %s(%hhu) missing",
				_dhcp_option_to_string(t), t);
			break;
		default:
			assert(false);
		}
	}

	return r;
}

static bool client_send_called = false;

static int fake_transport_send(struct dhcp_transport *transport,
				const struct sockaddr_in *dest,
				const void *data, size_t len)
{
	assert(len <= sizeof(client_packet));
	assert(!client_send_called);
	memcpy(client_packet, data, len);
	client_packet_len = len;
	client_send_called = true;

	return len;
}

static int fake_transport_l2_send(struct dhcp_transport *transport,
					uint32_t saddr, uint16_t sport,
					uint32_t daddr, uint16_t dport,
					const uint8_t *dest_mac,
					const void *data, size_t len)
{
	assert(len <= sizeof(client_packet));
	assert(!client_send_called);
	memcpy(client_packet, data, len);
	client_packet_len = len;
	client_send_called = true;

	return len;
}

static void event_handler_lease_obtained(struct l_dhcp_client *client,
						enum l_dhcp_client_event event,
						void *userdata)
{
	assert(client);
	assert(event == L_DHCP_CLIENT_EVENT_LEASE_OBTAINED);
	event_handler_called = true;
}

static void test_discover(const void *data)
{
	static const uint8_t addr[6] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
	struct l_dhcp_client *client;
	struct dhcp_transport *transport = l_new(struct dhcp_transport, 1);
	const struct l_dhcp_lease *lease;

	transport->send = fake_transport_send;
	transport->l2_send = fake_transport_l2_send;
	transport->ifindex = 42;

	client = l_dhcp_client_new(42);
	assert(l_dhcp_client_set_address(client, ARPHRD_ETHER, addr, 6));
	assert(l_dhcp_client_set_interface_name(client, "fake"));
	assert(_dhcp_client_set_transport(client, transport));
	assert(l_dhcp_client_set_hostname(client, "<hostname>"));
	_dhcp_client_override_xid(client, 0x4d7c67c6);
	assert(l_dhcp_client_set_event_handler(client,
				event_handler_lease_obtained, NULL, NULL));

	assert(l_dhcp_client_start(client));

	assert(client_send_called);
	client_send_called = false;
	assert(dhcp_message_compare(discover_data_1, sizeof(discover_data_1),
					client_packet, client_packet_len));

	transport->rx_cb(offer_data_1, sizeof(offer_data_1), client, NULL, 0);

	assert(client_send_called);
	client_send_called = false;
	assert(dhcp_message_compare(request_data_1, sizeof(request_data_1),
					client_packet, client_packet_len));

	event_handler_called = false;
	transport->rx_cb(ack_data_1, sizeof(ack_data_1), client, NULL, 0);
	assert(!client_send_called);
	assert(event_handler_called);

	lease = l_dhcp_client_get_lease(client);
	assert(lease);

	assert(lease->server_address == L_CPU_TO_BE32(0xc0a80101));
	assert(lease->subnet_mask == L_CPU_TO_BE32(0xffffff00));
	assert(lease->broadcast == L_CPU_TO_BE32(0xc0a801ff));
	assert(lease->router == L_CPU_TO_BE32(0xc0a80101));
	assert(lease->address == L_CPU_TO_BE32(0xc0a801f9));

	assert(lease->lifetime == 0x00015180);
	assert(lease->t1 == 0x0000a8c0);
	assert(lease->t2 == 0x00012750);

	l_dhcp_client_destroy(client);
	assert(client_send_called);
	client_send_called = false;
}

static bool l2_send_called = false;

static int fake_transport_server_l2_send(struct dhcp_transport *s,
					uint32_t source_ip,
					uint16_t source_port,
					uint32_t dest_ip,
					uint16_t dest_port,
					const uint8_t *dest_arp,
					const void *data, size_t len)
{
	assert(len <= sizeof(server_packet));
	assert(!l2_send_called);
	memcpy(server_packet, data, len);
	server_packet_len = len;

	l2_send_called = true;

	return 0;
}

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static char *new_client;
static char *expired_client;

static void server_event(struct l_dhcp_server *server,
					enum l_dhcp_server_event event,
					void *user_data,
					const struct l_dhcp_lease *lease)
{
	switch (event) {
	case L_DHCP_SERVER_EVENT_NEW_LEASE:
		assert(!new_client);
		new_client = l_dhcp_lease_get_address(lease);
		break;
	case L_DHCP_SERVER_EVENT_LEASE_EXPIRED:
		assert(!expired_client);
		expired_client = l_dhcp_lease_get_address(lease);
		break;
	}
}

static struct l_dhcp_client *client_init(const uint8_t *mac)
{
	struct l_dhcp_client *client = l_dhcp_client_new(42);
	struct dhcp_transport *transport = l_new(struct dhcp_transport, 1);

	assert(l_dhcp_client_set_address(client, ARPHRD_ETHER, mac, 6));
	assert(l_dhcp_client_set_interface_name(client, "fake"));
	assert(l_dhcp_client_set_hostname(client, "<hostname>"));
	_dhcp_client_override_xid(client, 0x4d7c67c6);
	assert(l_dhcp_client_set_event_handler(client,
				event_handler_lease_obtained, NULL, NULL));

	if (verbose)
		l_dhcp_client_set_debug(client, do_debug, "[DHCP1] ", NULL,
					L_LOG_DEBUG);

	transport->send = fake_transport_send;
	transport->l2_send = fake_transport_l2_send;
	transport->ifindex = 42;

	assert(_dhcp_client_set_transport(client, transport));

	return client;
}

static void client_connect(struct l_dhcp_client *client,
				struct l_dhcp_server *server, bool rapid_commit)
{
	struct dhcp_transport *srv_transport =
					_dhcp_server_get_transport(server);
	struct dhcp_transport *cli_transport =
					_dhcp_client_get_transport(client);
	uint8_t cli_addr[ETH_ALEN];
	const struct dhcp_message *msg = (struct dhcp_message *) client_packet;

	assert(l_dhcp_client_start(client));
	assert(client_send_called);
	client_send_called = false;
	memcpy(cli_addr, msg->chaddr, ETH_ALEN);

	/* RX DISCOVER */
	srv_transport->rx_cb(client_packet, client_packet_len, server,
				cli_addr, 0);
	assert(l2_send_called);
	l2_send_called = false;

	if (!rapid_commit) {
		/* RX OFFER */
		cli_transport->rx_cb(server_packet, server_packet_len, client,
					NULL, 0);
		assert(client_send_called);
		client_send_called = false;

		/* RX REQUEST */
		srv_transport->rx_cb(client_packet, client_packet_len, server,
					cli_addr, 0);
		assert(l2_send_called);
		l2_send_called = false;
	}

	/* RX ACK */
	cli_transport->rx_cb(server_packet, server_packet_len, client, NULL, 0);
	assert(!client_send_called);

	assert(event_handler_called);
}

static struct l_dhcp_server *server_init()
{
	char *dns[] = { "192.168.1.1", "192.168.1.254", NULL };
	struct l_dhcp_server *server = l_dhcp_server_new(41);
	struct dhcp_transport *srv_transport = l_new(struct dhcp_transport, 1);

	assert(l_dhcp_server_set_interface_name(server, "fake"));
	assert(l_dhcp_server_set_ip_address(server, "192.168.1.1"));
	assert(l_dhcp_server_set_netmask(server, "255.255.255.0"));
	assert(l_dhcp_server_set_gateway(server, "192.168.1.1"));
	assert(l_dhcp_server_set_dns(server, dns));
	assert(l_dhcp_server_set_event_handler(server, server_event,
						NULL, NULL));

	if (verbose)
		l_dhcp_server_set_debug(server, do_debug, "[DHCP SERV] ", NULL);

	srv_transport->ifindex = 41;
	srv_transport->l2_send = fake_transport_server_l2_send;

	assert(_dhcp_server_set_transport(server, srv_transport));

	assert(l_dhcp_server_start(server));

	return server;
}

static void test_complete_run(const void *data)
{
	bool rapid_commit = L_PTR_TO_UINT(data);
	static const uint8_t addr1[6] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
	static const uint8_t addr2[6] = { 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
	struct dhcp_transport *srv_transport;

	struct l_dhcp_client *client1;
	struct l_dhcp_client *client2;
	struct l_dhcp_server *server;

	const struct l_dhcp_lease *cli_lease;
	/* client IP address */
	char *cli_addr;
	/* servers IP address */
	char *srv_addr;
	char *tmp_addr;
	char **dns_list;

	server = server_init();
	l_dhcp_server_set_enable_rapid_commit(server, rapid_commit);

	assert(l_dhcp_server_set_ip_range(server, "192.168.1.2",
						"192.168.1.100"));

	srv_transport = _dhcp_server_get_transport(server);

	client1 = client_init(addr1);

	client_connect(client1, server, rapid_commit);

	cli_lease = l_dhcp_client_get_lease(client1);
	assert(cli_lease);
	cli_addr = l_dhcp_lease_get_address(cli_lease);
	assert(cli_addr);
	assert(!strcmp(cli_addr, "192.168.1.2"));
	assert(new_client);
	assert(!strcmp(new_client, cli_addr));
	l_free(new_client);
	new_client = NULL;

	srv_addr = l_dhcp_lease_get_server_id(cli_lease);
	assert(!strcmp(srv_addr, "192.168.1.1"));
	l_free(srv_addr);
	l_free(cli_addr);

	tmp_addr = l_dhcp_lease_get_gateway(cli_lease);
	assert(!strcmp(tmp_addr, "192.168.1.1"));
	l_free(tmp_addr);

	tmp_addr = l_dhcp_lease_get_netmask(cli_lease);
	assert(!strcmp(tmp_addr, "255.255.255.0"));
	l_free(tmp_addr);

	assert(l_dhcp_lease_get_prefix_length(cli_lease) == 24);

	dns_list = l_dhcp_lease_get_dns(cli_lease);
	assert(dns_list && dns_list[0] && dns_list[1]);
	assert(!strcmp(dns_list[0], "192.168.1.1"));
	assert(!strcmp(dns_list[1], "192.168.1.254"));
	l_strv_free(dns_list);

	client2 = client_init(addr2);

	client_connect(client2, server, rapid_commit);

	cli_lease = l_dhcp_client_get_lease(client2);
	assert(cli_lease);
	cli_addr = l_dhcp_lease_get_address(cli_lease);
	assert(cli_addr);
	assert(!strcmp(cli_addr, "192.168.1.3"));
	assert(new_client);
	assert(!strcmp(new_client, cli_addr));
	l_free(new_client);
	new_client = NULL;
	srv_addr = l_dhcp_lease_get_server_id(cli_lease);
	assert(!strcmp(srv_addr, "192.168.1.1"));
	l_free(srv_addr);
	l_free(cli_addr);

	l_dhcp_client_stop(client1);
	assert(client_send_called);
	client_send_called = false;
	srv_transport->rx_cb(client_packet, client_packet_len, server, addr1,
				0);
	assert(expired_client);
	assert(!strcmp(expired_client, "192.168.1.2"));
	l_free(expired_client);
	expired_client = NULL;

	l_dhcp_client_stop(client2);
	assert(client_send_called);
	client_send_called = false;
	srv_transport->rx_cb(client_packet, client_packet_len, server, addr2,
				0);
	assert(expired_client);
	assert(!strcmp(expired_client, "192.168.1.3"));
	l_free(expired_client);
	expired_client = NULL;

	l_dhcp_client_destroy(client1);
	assert(!client_send_called);
	l_dhcp_client_destroy(client2);
	assert(!client_send_called);

	l_dhcp_server_stop(server);
	l_dhcp_server_destroy(server);
}

static void test_expired_ip_reuse(const void *data)
{
	uint8_t addr[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x00};
	struct l_dhcp_server *server = server_init();
	struct dhcp_transport *srv_transport =
					_dhcp_server_get_transport(server);
	struct l_dhcp_client *client_new;
	const struct l_dhcp_lease *lease;
	char *cli_addr;
	int i;

	l_dhcp_server_set_ip_range(server, "192.168.1.2", "192.168.1.11");
	_dhcp_server_set_max_expired_clients(server, 10);
	l_dhcp_server_set_enable_rapid_commit(server, false);

	/*
	 * Connect and release 10 clients, this should max out the expired
	 * queue (since we are setting it to 10) and force the first client that
	 * expired to be removed allowing 192.168.1.2 to be reused for a new
	 * client
	 */
	for (i = 0; i < 10; i++) {
		struct l_dhcp_client *client;

		addr[5] = i;
		client = client_init(addr);
		client_connect(client, server, false);
		l_free(new_client);
		new_client = NULL;

		l_dhcp_client_destroy(client);
		assert(client_send_called);
		client_send_called = false;
		srv_transport->rx_cb(client_packet, client_packet_len, server,
					addr, 0);
		l_free(expired_client);
		expired_client = NULL;
	}

	addr[5] = i + 1;
	client_new = client_init(addr);
	client_connect(client_new, server, false);
	l_free(new_client);
	new_client = NULL;

	lease = l_dhcp_client_get_lease(client_new);
	assert(lease);
	cli_addr = l_dhcp_lease_get_address(lease);
	assert(!strcmp(cli_addr, "192.168.1.2"));
	l_free(cli_addr);

	l_dhcp_client_destroy(client_new);
	assert(client_send_called);
	client_send_called = false;
	l_dhcp_server_destroy(server);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("request-option", test_request_option, NULL);
	l_test_add("invalid-message-length", test_invalid_message_length, NULL);
	l_test_add("cookie", test_cookie, NULL);

	l_test_add("option test 1", test_option_1, &option_test_1);
	l_test_add("option test 2", test_option_2, &option_test_2);
	l_test_add("option test 3", test_option_3, &option_test_3);
	l_test_add("option test 4", test_option_4, &option_test_4);
	l_test_add("option test 5", test_option_5, &option_test_5);
	l_test_add("option test 6", test_option_6, &option_test_6);
	l_test_add("option test 7", test_option_7, &option_test_7);
	l_test_add("option test 8", test_option_8, &option_test_8);

	l_test_add("option set", test_option_set, NULL);

	l_test_add("checksum", test_checksum, NULL);

	l_test_add("discover", test_discover, NULL);

	l_test_add("complete run", test_complete_run, L_UINT_TO_PTR(false));
	l_test_add("rapid commit", test_complete_run, L_UINT_TO_PTR(true));
	l_test_add("expired IP reuse", test_expired_ip_reuse, NULL);

	return l_test_run();
}

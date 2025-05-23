/*
 * Embedded Linux library
 * Copyright (C) 2011-2014  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <stdio.h>
#include <linux/genetlink.h>
#include <ell/ell.h>

#include "ell/netlink-private.h"

static bool do_print = false;

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	printf("%s%s\n", prefix, str);
}

static unsigned char set_station_request[] = {
	0x34, 0x00, 0x00, 0x00, 0x17, 0x00, 0x05, 0x00, 0x8b, 0x53, 0x0d, 0x55,
	0x14, 0x0e, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00,
	0x03, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x06, 0x00, 0x24, 0xa2, 0xe1, 0xec,
	0x17, 0x04, 0x00, 0x00, 0x0c, 0x00, 0x43, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x00, 0x00,
};

struct set_station_test {
	uint8_t mac[6];
	uint32_t ifindex;
	uint32_t flags[2];
	uint32_t seq;
	uint32_t pid;
};

static const struct set_station_test set_station = {
	.mac = { 0x24, 0xa2, 0xe1, 0xec, 0x17, 0x04 },
	.ifindex = 3,
	.flags = { 2, 2 },
	.seq = 0x550d538b,
	.pid = 3604,
};

static void parse_set_station(const void *data)
{
	const struct set_station_test *test = data;
	struct nlmsghdr *nlmsg;
	struct l_genl_msg *msg;
	struct l_genl_attr attr;
	bool result;
	uint16_t type;
	uint16_t len;
	const void *payload;

	nlmsg = (struct nlmsghdr *) set_station_request;
	msg = l_genl_msg_new_from_data(nlmsg, sizeof(set_station_request));
	assert(msg);

	assert(l_genl_msg_get_command(msg) == 18);

	result = l_genl_attr_init(&attr, msg);
	assert(result);

	/*Interface Index: 3 (0x00000003) */
	assert(l_genl_attr_next(&attr, &type, &len, &payload));
	assert(type == 3);
	assert(len == 4);
	assert(*((unsigned int *) payload) == test->ifindex);

	/* MAC Address 24:A2:E1:EC:17:04 */
	assert(l_genl_attr_next(&attr, &type, &len, &payload));
	assert(type == 6);
	assert(len == sizeof(test->mac));
	assert(!memcmp(payload, test->mac, sizeof(test->mac)));

	/* Station Flags 2: len 8
	 *     Mask: 0x00000002
	 *         Authorized
	 *     Set: 0x00000002
	 *         Authorized
	 */
	assert(l_genl_attr_next(&attr, &type, &len, &payload));
	assert(type == 67);
	assert(len == sizeof(test->flags));
	assert(((unsigned int *) payload)[0] == test->flags[0]);
	assert(((unsigned int *) payload)[1] == test->flags[1]);

	l_genl_msg_unref(msg);
}

static void build_set_station(const void *data)
{
	const struct set_station_test *test = data;
	struct l_genl_msg *msg;
	const void *raw;
	size_t size;

	msg = l_genl_msg_new_sized(18, 512);
	assert(msg);

	assert(l_genl_msg_append_attr(msg, 3,
					sizeof(test->ifindex), &test->ifindex));
	assert(l_genl_msg_append_attr(msg, 6, sizeof(test->mac), test->mac));
	assert(l_genl_msg_append_attr(msg, 67,
					sizeof(test->flags), test->flags));

	raw = l_genl_msg_to_data(msg, 0x17, NLM_F_REQUEST | NLM_F_ACK,
					test->seq, test->pid, &size);

	if (do_print) {
		l_util_hexdump(false, raw, size, do_debug, "[MSG] ");
		l_util_hexdump(true, set_station_request,
					sizeof(set_station_request),
					do_debug, "[MSG] ");
	}

	assert(size == sizeof(set_station_request));
	assert(!memcmp(raw, set_station_request, size));

	l_genl_msg_unref(msg);
}

static void build_set_station_netlink(const void *data)
{
	const struct set_station_test *test = data;
	struct l_netlink_message *m;
	struct genlmsghdr genlhdr = { .cmd = 18, .version = 0, .reserved = 0 };

	m = l_netlink_message_new(0x17, 0);
	assert(m);

	assert(!l_netlink_message_add_header(m, &genlhdr, sizeof(genlhdr)));
	assert(!l_netlink_message_append_u32(m, 3, test->ifindex));
	assert(!l_netlink_message_append_mac(m, 6, test->mac));
	assert(!l_netlink_message_append(m, 67,
					test->flags, sizeof(test->flags)));

	m->hdr->nlmsg_seq = test->seq;
	m->hdr->nlmsg_pid = test->pid;

	if (do_print) {
		l_util_hexdump(false, m->data, m->hdr->nlmsg_len,
					do_debug, "[MSG] ");
		l_util_hexdump(true, set_station_request,
				sizeof(set_station_request), do_debug, "[MSG] ");
	}

	m->hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	assert(m->hdr->nlmsg_len == sizeof(set_station_request));
	assert(!memcmp(m->data, set_station_request,
					sizeof(set_station_request)));

	l_netlink_message_unref(m);
}

static const unsigned char set_rekey_offload_request[] = {
	0x54, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x05, 0x00, 0x59, 0xa3, 0xe1, 0x53,
	0xba, 0x02, 0x40, 0xe7, 0x4f, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00,
	0x03, 0x00, 0x00, 0x00, 0x38, 0x00, 0x7a, 0x80, 0x14, 0x00, 0x01, 0x00,
	0x2f, 0x82, 0xbb, 0x0d, 0x93, 0x56, 0x60, 0x4b, 0xb1, 0x55, 0x1c, 0x85,
	0xc0, 0xeb, 0x32, 0x8b, 0x14, 0x00, 0x02, 0x00, 0x43, 0x25, 0xcf, 0x08,
	0x0b, 0x92, 0xa7, 0x2d, 0x86, 0xdc, 0x43, 0x21, 0xd6, 0x0c, 0x12, 0x03,
	0x0c, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};

struct set_rekey_offload_test {
	uint32_t seq;
	uint32_t pid;
	uint32_t ifindex;
	uint8_t kek[16];
	uint8_t kck[16];
	uint8_t replay_counter[8];
};

static const struct set_rekey_offload_test rekey_offload = {
	.seq = 0x53e1a359,
	.pid = 0xe74002ba,
	.kek = {	0x2f, 0x82, 0xbb, 0x0d, 0x93, 0x56, 0x60, 0x4b,
			0xb1, 0x55, 0x1c, 0x85, 0xc0, 0xeb, 0x32, 0x8b },
	.kck = {	0x43, 0x25, 0xcf, 0x08, 0x0b, 0x92, 0xa7, 0x2d,
			0x86, 0xdc, 0x43, 0x21, 0xd6, 0x0c, 0x12, 0x03 },
	.replay_counter = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
	.ifindex = 3,
};

static void parse_set_rekey_offload(const void *data)
{
	const struct set_rekey_offload_test *test = data;
	struct nlmsghdr *nlmsg;
	struct l_genl_msg *msg;
	struct l_genl_attr attr;
	struct l_genl_attr nested;
	bool result;
	uint16_t type;
	uint16_t len;
	const void *payload;

	nlmsg = (struct nlmsghdr *) set_rekey_offload_request;
	msg = l_genl_msg_new_from_data(nlmsg,
					sizeof(set_rekey_offload_request));
	assert(msg);

	assert(l_genl_msg_get_command(msg) == 79);

	result = l_genl_attr_init(&attr, msg);
	assert(result);

	/*Interface Index: 3 (0x00000003) */
	assert(l_genl_attr_next(&attr, &type, &len, &payload));
	assert(type == 3);
	assert(len == 4);
	assert(*((unsigned int *) payload) == 3);

	/*
	 * Rekey Data: len 52
	 *     KEK: len 16
	 *         2f 82 bb 0d 93 56 60 4b b1 55 1c 85 c0 eb 32 8b
	 *     KCK: len 16
	 *         43 25 cf 08 0b 92 a7 2d 86 dc 43 21 d6 0c 12 03
	 *     Replay CTR: len 8
	 *         00 00 00 00 00 00 00 01
	 */
	assert(l_genl_attr_next(&attr, &type, &len, &payload));
	assert(type == 122);
	assert(len == 52);

	assert(l_genl_attr_recurse(&attr, &nested));

	assert(l_genl_attr_next(&nested, &type, &len, &payload));
	assert(type == 1);
	assert(len == sizeof(test->kek));
	assert(!memcmp(payload, test->kek, sizeof(test->kek)));

	assert(l_genl_attr_next(&nested, &type, &len, &payload));
	assert(type == 2);
	assert(len == sizeof(test->kck));
	assert(!memcmp(payload, test->kck, sizeof(test->kck)));

	assert(l_genl_attr_next(&nested, &type, &len, &payload));
	assert(type == 3);
	assert(len == sizeof(test->replay_counter));
	assert(!memcmp(payload, test->replay_counter, len));

	l_genl_msg_unref(msg);
}

static void build_set_rekey_offload(const void *data)
{
	const struct set_rekey_offload_test *test = data;
	struct l_genl_msg *msg;
	const void *raw;
	size_t size;

	msg = l_genl_msg_new_sized(79, 0);
	assert(msg);

	assert(l_genl_msg_append_attr(msg, 3,
					sizeof(test->ifindex), &test->ifindex));

	assert(l_genl_msg_enter_nested(msg, 122));
	assert(l_genl_msg_append_attr(msg, 1, sizeof(test->kek), test->kek));
	assert(l_genl_msg_append_attr(msg, 2, sizeof(test->kck), test->kck));
	assert(l_genl_msg_append_attr(msg, 3, sizeof(test->replay_counter),
						test->replay_counter));
	assert(l_genl_msg_leave_nested(msg));

	raw = l_genl_msg_to_data(msg, 0x1b, NLM_F_REQUEST | NLM_F_ACK,
					test->seq, test->pid, &size);

	if (do_print) {
		l_util_hexdump(false, raw, size, do_debug, "[MSG] ");
		l_util_hexdump(true, set_rekey_offload_request, size,
					do_debug, "[MSG] ");
	}

	assert(size == sizeof(set_rekey_offload_request));
	assert(!memcmp(raw, set_rekey_offload_request, size));

	l_genl_msg_unref(msg);
}

static void build_set_rekey_offload_netlink(const void *data)
{
	const struct set_rekey_offload_test *test = data;
	struct l_netlink_message *m;
	struct genlmsghdr genlhdr = { .cmd = 79, .version = 0, .reserved = 0 };

	m = l_netlink_message_new(0x1b, 0);
	assert(m);

	assert(!l_netlink_message_add_header(m, &genlhdr, sizeof(genlhdr)));
	assert(!l_netlink_message_append_u32(m, 3, test->ifindex));
	assert(!l_netlink_message_enter_nested(m, 122));
	assert(!l_netlink_message_append(m, 1, test->kek, sizeof(test->kek)));
	assert(!l_netlink_message_append(m, 2, test->kck, sizeof(test->kck)));
	assert(!l_netlink_message_append(m, 3, test->replay_counter,
						sizeof(test->replay_counter)));
	assert(!l_netlink_message_leave_nested(m));

	m->hdr->nlmsg_seq = test->seq;
	m->hdr->nlmsg_pid = test->pid;

	if (do_print) {
		l_util_hexdump(false, m->data, m->hdr->nlmsg_len,
					do_debug, "[MSG] ");
		l_util_hexdump(true, set_rekey_offload_request,
				sizeof(set_rekey_offload_request),
				do_debug, "[MSG] ");
	}

	m->hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	assert(m->hdr->nlmsg_len == sizeof(set_rekey_offload_request));
	assert(!memcmp(m->data, set_rekey_offload_request,
					sizeof(set_rekey_offload_request)));

	l_netlink_message_unref(m);
}

/*
 * This example is generated by libnl:
	msg = nlmsg_alloc();
	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, ops.o_id,
			0, 0, TASKSTATS_CMD_GET, TASKSTATS_GENL_VERSION);
	nla_put_u32(msg, TASKSTATS_CMD_ATTR_PID, 1);

	nest1 = nla_nest_start(msg, 0x45);
	nla_put_string(msg, 0x46, "f");
	nla_put_string(msg, 0x47, "foob");
	nla_put_string(msg, 0x48, "foobar");

	nest2 = nla_nest_start(msg, 0x49);
	nla_put_string(msg, 0x50, "ba");
	nla_nest_end(msg, nest2);
	nla_nest_end(msg, nest1);
*/

static const unsigned char libnl_nested[] = {
	0x4c, 0x00, 0x00, 0x00, 0x15, 0x00, 0x05, 0x00, 0x72, 0x05, 0x13, 0x55,
	0x77, 0x68, 0x40, 0x0c, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x30, 0x00, 0x45, 0x80, 0x06, 0x00, 0x46, 0x00,
	0x66, 0x00, 0x00, 0x00, 0x09, 0x00, 0x47, 0x00, 0x66, 0x6f, 0x6f, 0x62,
	0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x48, 0x00, 0x66, 0x6f, 0x6f, 0x62,
	0x61, 0x72, 0x00, 0x00, 0x0c, 0x00, 0x49, 0x80, 0x07, 0x00, 0x50, 0x00,
	0x62, 0x61, 0x00, 0x00,
};

static void parse_libnl_nested(const void *data)
{
	struct nlmsghdr *nlmsg;
	struct l_genl_msg *msg;
	struct l_genl_attr attr;
	struct l_genl_attr nested1;
	struct l_genl_attr nested2;
	bool result;
	uint16_t type;
	uint16_t len;
	const void *payload;

	nlmsg = (struct nlmsghdr *) libnl_nested;
	msg = l_genl_msg_new_from_data(nlmsg, sizeof(libnl_nested));
	assert(msg);

	assert(l_genl_msg_get_command(msg) == 1);

	result = l_genl_attr_init(&attr, msg);
	assert(result);

	assert(l_genl_attr_next(&attr, &type, &len, &payload));
	assert(type == 1);
	assert(len == 4);
	assert(*((unsigned int *) payload) == 1);

	assert(l_genl_attr_next(&attr, &type, &len, &payload));
	assert(type == 0x45);
	assert(len == 44);

	assert(l_genl_attr_recurse(&attr, &nested1));

	assert(l_genl_attr_next(&nested1, &type, &len, &payload));
	assert(type == 0x46);
	assert(len == 2);
	assert(!strcmp(payload, "f"));

	assert(l_genl_attr_next(&nested1, &type, &len, &payload));
	assert(type == 0x47);
	assert(len == 5);
	assert(!strcmp(payload, "foob"));

	assert(l_genl_attr_next(&nested1, &type, &len, &payload));
	assert(type == 0x48);
	assert(len == 7);
	assert(!strcmp(payload, "foobar"));

	assert(l_genl_attr_next(&nested1, &type, &len, &payload));
	assert(type == 0x49);
	assert(len == 8);

	assert(l_genl_attr_recurse(&nested1, &nested2));
	assert(l_genl_attr_next(&nested2, &type, &len, &payload));
	assert(type == 0x50);
	assert(len == 3);
	assert(!strcmp(payload, "ba"));

	l_genl_msg_unref(msg);
}

static void build_libnl_nested(const void *data)
{
	static uint32_t index = 1;
	struct l_genl_msg *msg;
	const void *raw;
	size_t size;

	msg = l_genl_msg_new_sized(1, 16);
	assert(msg);

	assert(l_genl_msg_append_attr(msg, 1, 4, &index));

	assert(l_genl_msg_enter_nested(msg, 0x45));
	assert(l_genl_msg_append_attr(msg, 0x46, 2, "f"));
	assert(l_genl_msg_append_attr(msg, 0x47, 5, "foob"));
	assert(l_genl_msg_append_attr(msg, 0x48, 7, "foobar"));
	assert(l_genl_msg_enter_nested(msg, 0x49));
	assert(l_genl_msg_append_attr(msg, 0x50, 3, "ba"));
	assert(l_genl_msg_leave_nested(msg));
	assert(l_genl_msg_leave_nested(msg));

	raw = l_genl_msg_to_data(msg, 0x15, 0x05, 0x55130572, 0x0c406877,
					&size);
	if (do_print) {
		l_util_hexdump(false, raw, size, do_debug, "[MSG] ");
		l_util_hexdump(true, libnl_nested, sizeof(libnl_nested),
							do_debug, "[MSG] ");
	}

	assert(size == sizeof(libnl_nested));
	assert(!memcmp(raw, libnl_nested, size));

	l_genl_msg_unref(msg);
}

static void test_append_attrv(const void *data)
{
	static const int num_blocks = 3;
	unsigned char * const payload = set_station_request;
	const size_t total_len = L_ARRAY_SIZE(set_station_request);
	const size_t block_len = total_len / num_blocks;
	const struct iovec iov[] = {
	    {
		.iov_base = payload,
		.iov_len  = block_len
	    },
	    {
		.iov_base = payload + block_len,
		.iov_len  = block_len
	    },
	    {
		.iov_base = payload + block_len * 2,
		.iov_len  = total_len - block_len * 2
	    }
	};

	struct l_genl_msg *msg;
	const uint16_t type = 2;
	struct l_genl_attr attr;
	uint16_t attr_type;
	uint16_t attr_len;
	const void *attr_payload;

	assert(L_ARRAY_SIZE(iov) == num_blocks);

	msg = l_genl_msg_new_sized(1, NLA_HDRLEN + NLA_ALIGN(total_len));
	assert(msg);

	assert(l_genl_msg_append_attrv(msg, type, iov, L_ARRAY_SIZE(iov)));
	assert(l_genl_attr_init(&attr, msg));
	assert(l_genl_attr_next(&attr, &attr_type, &attr_len, &attr_payload));

	assert(type == attr_type);
	assert(total_len == attr_len);
	assert(memcmp(payload, attr_payload, total_len) == 0);

	l_genl_msg_unref(msg);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add_data_func("Parse Set Station Request",
				&set_station, parse_set_station,
				L_TEST_FLAG_LITTLE_ENDIAN_ONLY);
	l_test_add_data_func("Parse Set Rekey Offload Request",
				&rekey_offload, parse_set_rekey_offload,
				L_TEST_FLAG_LITTLE_ENDIAN_ONLY);

	l_test_add_data_func("Build Set Station Request",
				&set_station, build_set_station,
				L_TEST_FLAG_LITTLE_ENDIAN_ONLY);
	l_test_add_data_func("Build Set Station Request (Netlink)",
				&set_station, build_set_station_netlink,
				L_TEST_FLAG_LITTLE_ENDIAN_ONLY);
	l_test_add_data_func("Build Set Rekey Offload Request",
				&rekey_offload, build_set_rekey_offload,
				L_TEST_FLAG_LITTLE_ENDIAN_ONLY);
	l_test_add_data_func("Build Set Rekey Offload Request (Netlink)",
				&rekey_offload, build_set_rekey_offload_netlink,
				L_TEST_FLAG_LITTLE_ENDIAN_ONLY);

	l_test_add_func("libnl-generated Example with Nesting",
					parse_libnl_nested,
					L_TEST_FLAG_LITTLE_ENDIAN_ONLY);
	l_test_add_func("Build libnl-generated Example with Nesting",
					build_libnl_nested,
					L_TEST_FLAG_LITTLE_ENDIAN_ONLY);

	l_test_add_func("Test l_genl_msg_append_attrv",
					test_append_attrv, 0);

	return l_test_run();
}

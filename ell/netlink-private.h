/*
 * Embedded Linux library
 * Copyright (C) 2011-2014  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#define NLA_OK(nla,len)         ((len) >= (int) sizeof(struct nlattr) && \
				(nla)->nla_len >= sizeof(struct nlattr) && \
				(nla)->nla_len <= (len))
#define NLA_NEXT(nla,attrlen)	((attrlen) -= NLMSG_ALIGN((nla)->nla_len), \
				(struct nlattr*)(((char*)(nla)) + \
				NLMSG_ALIGN((nla)->nla_len)))

#define NLA_LENGTH(len)		(NLMSG_ALIGN(sizeof(struct nlattr)) + (len))
#define NLA_DATA(nla)		((void*)(((char*)(nla)) + NLA_LENGTH(0)))
#define NLA_PAYLOAD(nla)	((int)((nla)->nla_len) - NLA_LENGTH(0))

#ifndef NETLINK_EXT_ACK
#define NETLINK_EXT_ACK 11
enum nlmsgerr_attrs {
	NLMSGERR_ATTR_UNUSED,
	NLMSGERR_ATTR_MSG,
	NLMSGERR_ATTR_OFFS,
};
#define NLM_F_CAPPED   0x100
#define NLM_F_ACK_TLVS 0x200
#endif

struct l_netlink_message {
	int ref_count;
	uint32_t size;
	union { /* The actual data */
		struct nlmsghdr *hdr;
		void *data;
	};
	uint32_t nest_offset[4];
	uint8_t nest_level;
	bool sealed : 1;
};

bool netlink_parse_ext_ack_error(const struct nlmsghdr *nlmsg,
					const char **out_error_msg,
					uint32_t *out_error_offset);
int netlink_message_reserve_header(struct l_netlink_message *message,
					size_t header_len, void **out_header);
struct l_netlink_message *netlink_message_from_nlmsg(
						const struct nlmsghdr *nlmsg);

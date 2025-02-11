/*
 * Embedded Linux library
 * Copyright (C) 2011-2014  Intel Corporation
 * Copyright (C) 2020  Daniel Wagner <dwagner@suse.de>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>
#include <asm/types.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>
#include <linux/icmpv6.h>
#include <linux/if.h>
#include <sys/socket.h>
#include <assert.h>
#include <limits.h>

#include <ell/ell.h>
#include "ell/netlink-private.h"
#include "ell/rtnl-private.h"
#include "ell/useful.h"

static size_t rta_add_u8(void *rta_buf, unsigned short type, uint8_t value)
{
	struct rtattr *rta = rta_buf;

	rta->rta_len = RTA_LENGTH(sizeof(uint8_t));
	rta->rta_type = type;
	*((uint8_t *) RTA_DATA(rta)) = value;

	return RTA_SPACE(sizeof(uint8_t));
}

static size_t rta_add_u32(void *rta_buf, unsigned short type, uint32_t value)
{
	struct rtattr *rta = rta_buf;

	rta->rta_len = RTA_LENGTH(sizeof(uint32_t));
	rta->rta_type = type;
	*((uint32_t *) RTA_DATA(rta)) = value;

	return RTA_SPACE(sizeof(uint32_t));
}

static size_t rta_add_data(void *rta_buf, unsigned short type, const void *data,
								size_t data_len)
{
	struct rtattr *rta = rta_buf;

	rta->rta_len = RTA_LENGTH(data_len);
	rta->rta_type = type;
	memcpy(RTA_DATA(rta), data, data_len);

	return RTA_SPACE(data_len);
}

static size_t rta_add_address(void *rta_buf, unsigned short type,
				uint8_t family,
				const struct in6_addr *v6,
				const struct in_addr *v4)
{
	struct rtattr *rta = rta_buf;

	rta->rta_type = type;

	switch (family) {
	case AF_INET6:
		rta->rta_len = RTA_LENGTH(sizeof(struct in6_addr));
		memcpy(RTA_DATA(rta), v6, sizeof(struct in6_addr));
		return RTA_SPACE(sizeof(struct in6_addr));
	case AF_INET:
		rta->rta_len = RTA_LENGTH(sizeof(struct in_addr));
		memcpy(RTA_DATA(rta), v4, sizeof(struct in_addr));
		return RTA_SPACE(sizeof(struct in_addr));
	}

	return 0;
}

static int address_is_null(int family, const struct in_addr *v4,
						const struct in6_addr *v6)
{
	switch (family) {
	case AF_INET:
		return v4->s_addr == 0;
	case AF_INET6:
		return IN6_IS_ADDR_UNSPECIFIED(v6);
	}

	return -EAFNOSUPPORT;
}

static bool messages_equal(const struct l_netlink_message *nlm,
				void *other_message, size_t len)
{

	if (len != nlm->hdr->nlmsg_len - NLMSG_HDRLEN)
		return false;

	return !memcmp(nlm->data + NLMSG_HDRLEN, other_message, len);
}

static const struct l_rtnl_route route = {
	.family = AF_INET6,
	.scope = RT_SCOPE_UNIVERSE,
	.protocol = RTPROT_UNSPEC,
	.gw = { .in6_addr = IN6ADDR_LOOPBACK_INIT },
	.dst = { .in6_addr = IN6ADDR_LOOPBACK_INIT },
	.dst_prefix_len = 32,
	.prefsrc = { .in6_addr = IN6ADDR_LOOPBACK_INIT },
	.lifetime = INT_MAX,
	.expiry_time = 0, /* math performed, will cause messages to differ */
	.mtu = 8096,
	.priority = 300,
	.preference = ICMPV6_ROUTER_PREF_LOW,
};

static struct rtmsg *build_rtmsg(const struct l_rtnl_route *rt, int ifindex,
					size_t *out_len)
{
	struct rtmsg *rtmmsg;
	size_t bufsize;
	void *rta_buf;
	uint64_t now = l_time_now();

	bufsize = NLMSG_ALIGN(sizeof(struct rtmsg)) +
			RTA_SPACE(sizeof(uint32_t)) +        /* RTA_OIF */
			RTA_SPACE(sizeof(uint32_t)) +        /* RTA_PRIORITY */
			RTA_SPACE(sizeof(struct in6_addr)) + /* RTA_GATEWAY */
			RTA_SPACE(sizeof(struct in6_addr)) + /* RTA_DST */
			RTA_SPACE(sizeof(struct in6_addr)) + /* RTA_PREFSRC */
			256 +                                /* RTA_METRICS */
			RTA_SPACE(sizeof(uint8_t)) +         /* RTA_PREF */
			RTA_SPACE(sizeof(uint32_t));         /* RTA_EXPIRES */

	rtmmsg = l_malloc(bufsize);
	memset(rtmmsg, 0, bufsize);

	rtmmsg->rtm_family = rt->family;
	rtmmsg->rtm_table = RT_TABLE_MAIN;
	rtmmsg->rtm_protocol = rt->protocol;
	rtmmsg->rtm_type = RTN_UNICAST;
	rtmmsg->rtm_scope = rt->scope;

	rta_buf = (void *) rtmmsg + NLMSG_ALIGN(sizeof(struct rtmsg));
	rta_buf += rta_add_u32(rta_buf, RTA_OIF, ifindex);

	if (rt->priority)
		rta_buf += rta_add_u32(rta_buf, RTA_PRIORITY,
						rt->priority + ifindex);

	if (!address_is_null(rt->family, &rt->gw.in_addr, &rt->gw.in6_addr))
		rta_buf += rta_add_address(rta_buf, RTA_GATEWAY, rt->family,
					&rt->gw.in6_addr, &rt->gw.in_addr);

	if (rt->dst_prefix_len) {
		rtmmsg->rtm_dst_len = rt->dst_prefix_len;
		rta_buf += rta_add_address(rta_buf, RTA_DST, rt->family,
					&rt->dst.in6_addr, &rt->dst.in_addr);
	}

	if (!address_is_null(rt->family, &rt->prefsrc.in_addr,
						&rt->prefsrc.in6_addr))
		rta_buf += rta_add_address(rta_buf, RTA_PREFSRC, rt->family,
						&rt->prefsrc.in6_addr,
						&rt->prefsrc.in_addr);

	if (rt->mtu) {
		uint8_t buf[256];
		size_t written = rta_add_u32(buf, RTAX_MTU, rt->mtu);

		rta_buf += rta_add_data(rta_buf, RTA_METRICS | NLA_F_NESTED,
							buf, written);
	}

	if (rt->preference)
		rta_buf += rta_add_u8(rta_buf, RTA_PREF, rt->preference);

	if (rt->expiry_time > now)
		rta_buf += rta_add_u32(rta_buf, RTA_EXPIRES,
					l_time_to_secs(rt->expiry_time - now));

	*out_len = rta_buf - (void *) rtmmsg;
	return rtmmsg;
}

static void test_route(const void *data)
{
	static const int ifindex = 3;
	size_t rtmsg_len;
	_auto_(l_free) void *rtmsg = build_rtmsg(&route, ifindex, &rtmsg_len);
	struct l_netlink_message *nlm =
		rtnl_message_from_route(RTM_NEWROUTE,
					NLM_F_CREATE | NLM_F_REPLACE,
					ifindex, &route);

	assert(messages_equal(nlm, rtmsg, rtmsg_len));
	l_netlink_message_unref(nlm);
}

static const struct l_rtnl_address address = {
	.family = AF_INET6,
	.prefix_len = 31,
	.scope = RT_SCOPE_UNIVERSE,
	.in6_addr = IN6ADDR_LOOPBACK_INIT,
	.label = { 'f', 'o', 'o', 'b', 'a', 'r', '\0' },
	.flags = IFA_F_PERMANENT | IFA_F_NOPREFIXROUTE,
};

static struct ifaddrmsg *build_ifaddrmsg(const struct l_rtnl_address *addr,
						int ifindex, size_t *out_len)
{
	struct ifaddrmsg *ifamsg;
	void *buf;
	size_t bufsize;
	uint64_t now = l_time_now();

	bufsize = NLMSG_ALIGN(sizeof(struct ifaddrmsg)) +
					RTA_SPACE(sizeof(struct in6_addr)) +
					RTA_SPACE(sizeof(struct in_addr)) +
					RTA_SPACE(sizeof(uint32_t)) +
					RTA_SPACE(IFNAMSIZ) +
					RTA_SPACE(sizeof(struct ifa_cacheinfo));

	ifamsg = l_malloc(bufsize);
	memset(ifamsg, 0, bufsize);

	ifamsg->ifa_index = ifindex;
	ifamsg->ifa_family = addr->family;
	ifamsg->ifa_scope = addr->scope;
	ifamsg->ifa_prefixlen = addr->prefix_len;
	/* Kernel ignores legacy flags in IFA_FLAGS, so set them here */
	ifamsg->ifa_flags = addr->flags & 0xff;

	buf = (void *) ifamsg + NLMSG_ALIGN(sizeof(struct ifaddrmsg));

	if (addr->family == AF_INET) {
		buf += rta_add_data(buf, IFA_LOCAL, &addr->in_addr,
						sizeof(struct in_addr));
		buf += rta_add_data(buf, IFA_BROADCAST, &addr->broadcast,
						sizeof(struct in_addr));
	} else
		buf += rta_add_data(buf, IFA_LOCAL, &addr->in6_addr,
						sizeof(struct in6_addr));

	if (addr->flags & 0xffffff00)
		buf += rta_add_u32(buf, IFA_FLAGS, addr->flags & 0xffffff00);

	if (addr->label[0])
		buf += rta_add_data(buf, IFA_LABEL,
					addr->label, strlen(addr->label) + 1);

	if (addr->preferred_expiry_time > now ||
			addr->valid_expiry_time > now) {
		struct ifa_cacheinfo cinfo;

		memset(&cinfo, 0, sizeof(cinfo));
		cinfo.ifa_prefered = addr->preferred_expiry_time > now ?
			l_time_to_secs(addr->preferred_expiry_time - now) : 0;
		cinfo.ifa_valid =  addr->valid_expiry_time > now ?
			l_time_to_secs(addr->valid_expiry_time - now) : 0;

		buf += rta_add_data(buf, IFA_CACHEINFO, &cinfo, sizeof(cinfo));
	}

	*out_len = buf - (void *) ifamsg;
	return ifamsg;
}

_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Warray-bounds\"")
static void test_address(const void *data)
{
	static const int ifindex = 3;
	size_t ifamsg_len;
	_auto_(l_free) void *ifamsg =
				build_ifaddrmsg(&address, ifindex, &ifamsg_len);
	struct l_netlink_message *nlm =
		rtnl_message_from_address(RTM_NEWADDR,
					NLM_F_CREATE | NLM_F_REPLACE,
					ifindex, &address);

	assert(messages_equal(nlm, ifamsg, ifamsg_len));
	l_netlink_message_unref(nlm);
}
_Pragma("GCC diagnostic pop")

static void signal_handler(uint32_t signo, void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_info("Terminate");
		l_main_quit();
		break;
	}
}

static void route4_dump_cb(int error, uint16_t type, const void *data,
						uint32_t len, void *user_data)
{
	const struct rtmsg *rtmsg = data;
	char *dst = NULL, *gateway = NULL, *src = NULL;
	uint32_t table, ifindex;

	assert(!error);
	assert(type == RTM_NEWROUTE);

	l_rtnl_route4_extract(rtmsg, len, &table, &ifindex,
				&dst, &gateway, &src);

	l_info("table %d ifindex %d dst %s gateway %s src %s",
		table, ifindex, dst, gateway, src);

	l_free(dst);
	l_free(gateway);
	l_free(src);

	l_main_quit();
}

static void test_route4_dump(const void *data)
{
	struct l_netlink *rtnl;
	int exit_status;
	uint32_t id;

	assert(l_main_init());

	l_log_set_stderr();

	rtnl = l_netlink_new(NETLINK_ROUTE);
	assert(rtnl);

	id = l_rtnl_route4_dump(rtnl, route4_dump_cb, NULL, NULL);
	assert(id);

	exit_status = l_main_run_with_signal(signal_handler, NULL);
	assert(exit_status == EXIT_SUCCESS);

	l_netlink_destroy(rtnl);

	assert(l_main_exit());
}

static void route6_dump_cb(int error,
			uint16_t type, const void *data,
			uint32_t len, void *user_data)
{
	const struct rtmsg *rtmsg = data;
	char *dst = NULL, *gateway = NULL, *src = NULL;
	uint32_t table = 0, ifindex = 0;

	assert(!error);
	assert(type == RTM_NEWROUTE);

	l_rtnl_route6_extract(rtmsg, len, &table, &ifindex,
				&dst, &gateway, &src);

	l_info("table %d ifindex %d dst %s gateway %s src %s",
		table, ifindex, dst, gateway, src);

	l_free(dst);
	l_free(gateway);
	l_free(src);

	l_main_quit();
}

static void test_route6_dump(const void *data)
{
	struct l_netlink *rtnl;
	int exit_status;
	uint32_t id;

	assert(l_main_init());

	l_log_set_stderr();

	rtnl = l_netlink_new(NETLINK_ROUTE);
	assert(rtnl);

	id = l_rtnl_route6_dump(rtnl, route6_dump_cb, NULL, NULL);
	assert(id);

	exit_status = l_main_run_with_signal(signal_handler, NULL);
	assert(exit_status == EXIT_SUCCESS);

	l_netlink_destroy(rtnl);

	assert(l_main_exit());
}

static void ifaddr4_dump_cb(int error, uint16_t type, const void *data,
						uint32_t len, void *user_data)
{
	const struct ifaddrmsg *ifa = data;
	char *label = NULL, *ip = NULL, *broadcast = NULL;

	assert(!error);
	assert(type == RTM_NEWADDR);

	l_rtnl_ifaddr4_extract(ifa, len, &label, &ip, &broadcast);

	l_info("label %s ip %s broadcast %s", label, ip, broadcast);

	l_free(label);
	l_free(ip);
	l_free(broadcast);

	l_main_quit();
}

static void test_ifaddr4_dump(const void *data)
{
	struct l_netlink *rtnl;
	int exit_status;
	uint32_t id;

	assert(l_main_init());

	l_log_set_stderr();

	rtnl = l_netlink_new(NETLINK_ROUTE);
	assert(rtnl);

	id = l_rtnl_ifaddr4_dump(rtnl, ifaddr4_dump_cb, NULL, NULL);
	assert(id);

	exit_status = l_main_run_with_signal(signal_handler, NULL);
	assert(exit_status == EXIT_SUCCESS);

	l_netlink_destroy(rtnl);

	assert(l_main_exit());
}

static void ifaddr6_dump_cb(int error, uint16_t type, const void *data,
						uint32_t len, void *user_data)
{
	const struct ifaddrmsg *ifa = data;
	char *ip = NULL;

	assert(!error);
	assert(type == RTM_NEWADDR);

	l_rtnl_ifaddr6_extract(ifa, len, &ip);

	l_info("ip %s", ip);

	l_free(ip);

	l_main_quit();
}

static void test_ifaddr6_dump(const void *data)
{
	struct l_netlink *rtnl;
	int exit_status;
	uint32_t id;

	assert(l_main_init());

	l_log_set_stderr();

	rtnl = l_netlink_new(NETLINK_ROUTE);
	assert(rtnl);

	id = l_rtnl_ifaddr6_dump(rtnl, ifaddr6_dump_cb, NULL, NULL);
	assert(id);

	exit_status = l_main_run_with_signal(signal_handler, NULL);
	assert(exit_status == EXIT_SUCCESS);

	l_netlink_destroy(rtnl);

	assert(l_main_exit());
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("route", test_route, NULL);
	l_test_add("address", test_address, NULL);

	l_test_add("Dump IPv4 routing table", test_route4_dump, NULL);
	l_test_add("Dump IPv6 routing table", test_route6_dump, NULL);
	l_test_add("Dump IPv4 addresses", test_ifaddr4_dump, NULL);
	l_test_add("Dump IPv6 addresses", test_ifaddr6_dump, NULL);

	return l_test_run();
}

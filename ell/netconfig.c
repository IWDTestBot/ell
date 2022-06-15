/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2022  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <linux/types.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <net/if.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "private.h"
#include "useful.h"
#include "log.h"
#include "dhcp.h"
#include "dhcp-private.h"
#include "icmp6.h"
#include "icmp6-private.h"
#include "dhcp6.h"
#include "netlink.h"
#include "rtnl.h"
#include "rtnl-private.h"
#include "queue.h"
#include "time.h"
#include "idle.h"
#include "strv.h"
#include "net.h"
#include "net-private.h"
#include "netconfig.h"

struct l_netconfig {
	uint32_t ifindex;
	uint32_t route_priority;

	bool v4_enabled;
	struct l_rtnl_address *v4_static_addr;
	char *v4_gateway_override;
	char **v4_dns_override;
	char **v4_domain_names_override;

	bool v6_enabled;
	struct l_rtnl_address *v6_static_addr;
	char *v6_gateway_override;
	char **v6_dns_override;
	char **v6_domain_names_override;

	bool started;
	struct l_idle *do_static_work;
	bool v4_configured;
	struct l_dhcp_client *dhcp_client;
	bool v6_configured;
	struct l_icmp6_client *icmp6_client;
	struct l_dhcp6_client *dhcp6_client;
	struct l_idle *signal_expired_work;
	unsigned int ifaddr6_dump_cmd_id;
	struct l_queue *icmp_route_data;

	/* These objects, if not NULL, are owned by @addresses and @routes */
	struct l_rtnl_address *v4_address;
	struct l_rtnl_route *v4_subnet_route;
	struct l_rtnl_route *v4_default_route;
	struct l_rtnl_address *v6_address;

	struct {
		struct l_queue *current;

		/*
		 * Temporary lists for use by the UPDATED handler to avoid
		 * having to remove all entries on the interface and re-add
		 * them from @current.  Entries in @updated are those that
		 * RTM_NEWADDR/RTM_NEWROUTE will correctly identify as
		 * existing objects and replace (with NLM_F_REPLACE) or
		 * error out (without it) rather than create duplicates,
		 * for example those that only have their lifetime updated.
		 *
		 * Any entries in @added and @updated are owned by @current.
		 * Entries in @removed need to be removed with an
		 * RTM_DELADD/RTM_DELROUTE while those in @expired are only
		 * informative as the kernel will have removed them already.
		 */
		struct l_queue *added;
		struct l_queue *updated;
		struct l_queue *removed;
		struct l_queue *expired;
	} addresses, routes;

	struct {
		l_netconfig_event_cb_t callback;
		void *user_data;
		l_netconfig_destroy_cb_t destroy;
	} handler;
};

struct netconfig_route_data {
	struct l_rtnl_route *route;
	uint64_t last_ra_time;
	uint64_t kernel_expiry;
	uint64_t max_ra_interval;
};

union netconfig_addr {
	struct in_addr v4;
	struct in6_addr v6;
};

static struct l_queue *addr_wait_list;
static unsigned int rtnl_id;

static void netconfig_update_cleanup(struct l_netconfig *nc)
{
	l_queue_clear(nc->addresses.added, NULL);
	l_queue_clear(nc->addresses.updated, NULL);
	l_queue_clear(nc->addresses.removed,
			(l_queue_destroy_func_t) l_rtnl_address_free);
	l_queue_clear(nc->addresses.expired,
			(l_queue_destroy_func_t) l_rtnl_address_free);
	l_queue_clear(nc->routes.added, NULL);
	l_queue_clear(nc->routes.updated, NULL);
	l_queue_clear(nc->routes.removed,
			(l_queue_destroy_func_t) l_rtnl_route_free);
	l_queue_clear(nc->routes.expired,
			(l_queue_destroy_func_t) l_rtnl_route_free);
}

static void netconfig_emit_event(struct l_netconfig *nc, uint8_t family,
					enum l_netconfig_event event)
{
	if (!nc->handler.callback)
		return;

	nc->handler.callback(nc, family, event, nc->handler.user_data);

	if (L_IN_SET(event, L_NETCONFIG_EVENT_UPDATE,
			L_NETCONFIG_EVENT_CONFIGURE,
			L_NETCONFIG_EVENT_UNCONFIGURE))
		netconfig_update_cleanup(nc);
}

static struct l_rtnl_route *netconfig_route_new(struct l_netconfig *nc,
						uint8_t family,
						const void *dst,
						uint8_t prefix_len,
						const void *gw,
						uint8_t protocol)
{
	struct l_rtnl_route *rt = l_new(struct l_rtnl_route, 1);

	rt->family = family;
	rt->scope = (family == AF_INET && dst) ?
		RT_SCOPE_LINK : RT_SCOPE_UNIVERSE;
	rt->protocol = protocol;
	rt->lifetime = 0xffffffff;
	rt->priority = nc->route_priority;

	if (dst) {
		memcpy(&rt->dst, dst, family == AF_INET ? 4 : 16);
		rt->dst_prefix_len = prefix_len;
	}

	if (gw)
		memcpy(&rt->gw, gw, family == AF_INET ? 4 : 16);

	return rt;
}

static void netconfig_signal_expired(struct l_idle *idle, void *user_data)
{
	struct l_netconfig *nc = user_data;

	l_idle_remove(l_steal_ptr(nc->signal_expired_work));

	/*
	 * If the idle work was scheduled from within l_netconfig_get_routes
	 * or netconfig_icmp6_event_handler, the user is likely to have
	 * already received an event and had a chance to process the expired
	 * routes list.  In that case there's no need to emit a new event,
	 * and the list will have been emptied in netconfig_update_cleanup()
	 * anyway.
	 */
	if (!l_queue_isempty(nc->routes.expired))
		netconfig_emit_event(nc, AF_INET6, L_NETCONFIG_EVENT_UPDATE);
}

static void netconfig_add_v4_routes(struct l_netconfig *nc, const char *ip,
					uint8_t prefix_len, const char *gateway,
					uint8_t rtm_protocol)
{
	struct in_addr in_addr;

	/* Subnet route */

	if (L_WARN_ON(inet_pton(AF_INET, ip, &in_addr) != 1))
		return;

	in_addr.s_addr &= htonl(0xfffffffflu << (32 - prefix_len));
	nc->v4_subnet_route = netconfig_route_new(nc, AF_INET, &in_addr,
							prefix_len, NULL,
							rtm_protocol);
	l_queue_push_tail(nc->routes.current, nc->v4_subnet_route);
	l_queue_push_tail(nc->routes.added, nc->v4_subnet_route);

	/* Gateway route */

	if (nc->v4_gateway_override) {
		gateway = nc->v4_gateway_override;
		rtm_protocol = RTPROT_STATIC;
	}

	if (!gateway)
		return;

	nc->v4_default_route = l_rtnl_route_new_gateway(gateway);
	l_rtnl_route_set_protocol(nc->v4_default_route, rtm_protocol);
	L_WARN_ON(!l_rtnl_route_set_prefsrc(nc->v4_default_route, ip));
	l_rtnl_route_set_priority(nc->v4_default_route, nc->route_priority);
	l_queue_push_tail(nc->routes.current, nc->v4_default_route);
	l_queue_push_tail(nc->routes.added, nc->v4_default_route);
}

static void netconfig_add_v6_static_routes(struct l_netconfig *nc,
						const char *ip,
						uint8_t prefix_len)
{
	struct in6_addr in6_addr;
	const void *prefix;
	struct l_rtnl_route *v6_subnet_route;
	struct l_rtnl_route *v6_default_route;

	/* Subnet route */

	if (L_WARN_ON(inet_pton(AF_INET6, ip, &in6_addr) != 1))
		return;

	/*
	 * Zero out host address bits, aka. interface ID, to produce
	 * the network address or prefix.
	 */
	prefix = net_prefix_from_ipv6(in6_addr.s6_addr, prefix_len);

	/*
	 * One reason we add a subnet route instead of letting the kernel
	 * do it, by not specifying IFA_F_NOPREFIXROUTE for the address,
	 * is that that would force a 0 metric for the route.
	 */
	v6_subnet_route = netconfig_route_new(nc, AF_INET6, prefix, prefix_len,
						NULL, RTPROT_STATIC);
	l_queue_push_tail(nc->routes.current, v6_subnet_route);
	l_queue_push_tail(nc->routes.added, v6_subnet_route);

	/* Gateway route */

	if (!nc->v6_gateway_override)
		return;

	v6_default_route = l_rtnl_route_new_gateway(nc->v6_gateway_override);
	l_rtnl_route_set_protocol(v6_default_route, RTPROT_STATIC);
	/*
	 * TODO: Optimally we'd set the prefsrc on the route with:
	 * L_WARN_ON(!l_rtnl_route_set_prefsrc(v6_default_route, ip));
	 *
	 * but that means that we can only commit the route to the kernel
	 * with an RTM_NEWROUTE command after the corresponding RTM_NEWADDR
	 * has returned and the kernel has finished DAD for the address and
	 * cleared IFA_F_TENTATIVE.  That will complicate
	 * l_netconfig_apply_rtnl() significantly but may be inevitable.
	 */

	l_queue_push_tail(nc->routes.current, v6_default_route);
	l_queue_push_tail(nc->routes.added, v6_default_route);
}

static bool netconfig_address_exists(struct l_queue *list,
					const struct l_rtnl_address *address)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(list); entry;
			entry = entry->next)
		if ((const struct l_rtnl_address *) entry->data == address)
			return true;

	return false;
}

static bool netconfig_route_exists(struct l_queue *list,
					const struct l_rtnl_route *route)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(list); entry;
			entry = entry->next)
		if ((const struct l_rtnl_route *) entry->data == route)
			return true;

	return false;
}

static void netconfig_add_dhcp_address_routes(struct l_netconfig *nc)
{
	const struct l_dhcp_lease *lease =
		l_dhcp_client_get_lease(nc->dhcp_client);
	_auto_(l_free) char *ip = NULL;
	_auto_(l_free) char *broadcast = NULL;
	_auto_(l_free) char *gateway = NULL;
	uint32_t prefix_len;

	ip = l_dhcp_lease_get_address(lease);
	broadcast = l_dhcp_lease_get_broadcast(lease);

	prefix_len = l_dhcp_lease_get_prefix_length(lease);
	if (!prefix_len)
		prefix_len = 24;

	nc->v4_address = l_rtnl_address_new(ip, prefix_len);
	if (L_WARN_ON(!nc->v4_address))
		return;

	l_rtnl_address_set_noprefixroute(nc->v4_address, true);

	if (broadcast)
		l_rtnl_address_set_broadcast(nc->v4_address, broadcast);

	l_queue_push_tail(nc->addresses.current, nc->v4_address);
	l_queue_push_tail(nc->addresses.added, nc->v4_address);

	gateway = l_dhcp_lease_get_gateway(lease);
	netconfig_add_v4_routes(nc, ip, prefix_len, gateway, RTPROT_DHCP);
}

static void netconfig_set_dhcp_lifetimes(struct l_netconfig *nc, bool updated)
{
	const struct l_dhcp_lease *lease =
		l_dhcp_client_get_lease(nc->dhcp_client);
	uint32_t lifetime = l_dhcp_lease_get_lifetime(lease);
	uint64_t expiry = l_dhcp_lease_get_start_time(lease) +
		lifetime * L_USEC_PER_SEC;

	l_rtnl_address_set_lifetimes(nc->v4_address, 0, lifetime);
	l_rtnl_address_set_expiry(nc->v4_address, 0, expiry);

	if (updated && !netconfig_address_exists(nc->addresses.added,
							nc->v4_address))
		l_queue_push_tail(nc->addresses.updated, nc->v4_address);

	l_rtnl_route_set_lifetime(nc->v4_subnet_route, lifetime);
	l_rtnl_route_set_expiry(nc->v4_subnet_route, expiry);

	if (updated && !netconfig_route_exists(nc->routes.added,
						nc->v4_subnet_route))
		l_queue_push_tail(nc->routes.updated, nc->v4_subnet_route);

	if (!nc->v4_default_route)
		return;

	l_rtnl_route_set_lifetime(nc->v4_default_route, lifetime);
	l_rtnl_route_set_expiry(nc->v4_default_route, expiry);

	if (updated && !netconfig_route_exists(nc->routes.added,
						nc->v4_default_route))
		l_queue_push_tail(nc->routes.updated, nc->v4_default_route);
}

static void netconfig_remove_dhcp_address_routes(struct l_netconfig *nc,
							bool expired)
{
	struct l_queue *routes =
		expired ? nc->routes.expired : nc->routes.removed;

	l_queue_remove(nc->addresses.current, nc->v4_address);
	l_queue_remove(nc->addresses.updated, nc->v4_address);

	if (!l_queue_remove(nc->addresses.added, nc->v4_address))
		l_queue_push_tail(
			expired ? nc->addresses.expired : nc->addresses.removed,
			nc->v4_address);

	nc->v4_address = NULL;

	l_queue_remove(nc->routes.current, nc->v4_subnet_route);
	l_queue_remove(nc->routes.updated, nc->v4_subnet_route);

	if (!l_queue_remove(nc->routes.added, nc->v4_subnet_route))
		l_queue_push_tail(routes, nc->v4_subnet_route);

	nc->v4_subnet_route = NULL;

	if (nc->v4_default_route) {
		l_queue_remove(nc->routes.current, nc->v4_default_route);
		l_queue_remove(nc->routes.updated, nc->v4_default_route);

		if (!l_queue_remove(nc->routes.added, nc->v4_default_route))
			l_queue_push_tail(routes, nc->v4_default_route);

		nc->v4_default_route = NULL;
	}
}

static void netconfig_set_neighbor_entry_cb(int error,
						uint16_t type, const void *data,
						uint32_t len, void *user_data)
{
	/* Not critical.  TODO: log warning */
}

static int netconfig_dhcp_gateway_to_arp(struct l_netconfig *nc)
{
	const struct l_dhcp_lease *lease =
		l_dhcp_client_get_lease(nc->dhcp_client);
	_auto_(l_free) char *server_id = l_dhcp_lease_get_server_id(lease);
	_auto_(l_free) char *gw = l_dhcp_lease_get_gateway(lease);
	const uint8_t *server_mac = l_dhcp_lease_get_server_mac(lease);
	struct in_addr in_gw;

	if (!gw || strcmp(server_id, gw) || !server_mac)
		return -ENOENT;

	/* Gateway MAC is known, write it into ARP cache to save ARP traffic */
	in_gw.s_addr = l_dhcp_lease_get_gateway_u32(lease);

	if (!l_rtnl_neighbor_set_hwaddr(l_rtnl_get(), nc->ifindex, AF_INET,
					&in_gw, server_mac, ETH_ALEN,
					netconfig_set_neighbor_entry_cb, nc,
					NULL))
		return -EIO;

	return 0;
}

static void netconfig_dhcp_event_handler(struct l_dhcp_client *client,
						enum l_dhcp_client_event event,
						void *user_data)
{
	struct l_netconfig *nc = user_data;

	switch (event) {
	case L_DHCP_CLIENT_EVENT_IP_CHANGED:
		if (L_WARN_ON(!nc->v4_configured))
			break;

		netconfig_remove_dhcp_address_routes(nc, false);
		netconfig_add_dhcp_address_routes(nc);
		netconfig_set_dhcp_lifetimes(nc, false);
		netconfig_emit_event(nc, AF_INET, L_NETCONFIG_EVENT_UPDATE);
		break;
	case L_DHCP_CLIENT_EVENT_LEASE_OBTAINED:
		if (L_WARN_ON(nc->v4_configured))
			break;

		netconfig_add_dhcp_address_routes(nc);
		netconfig_set_dhcp_lifetimes(nc, false);
		nc->v4_configured = true;
		netconfig_emit_event(nc, AF_INET, L_NETCONFIG_EVENT_CONFIGURE);
		netconfig_dhcp_gateway_to_arp(nc);
		break;
	case L_DHCP_CLIENT_EVENT_LEASE_RENEWED:
		if (L_WARN_ON(!nc->v4_configured))
			break;

		netconfig_set_dhcp_lifetimes(nc, true);
		netconfig_emit_event(nc, AF_INET, L_NETCONFIG_EVENT_UPDATE);
		break;
	case L_DHCP_CLIENT_EVENT_LEASE_EXPIRED:
		if (L_WARN_ON(!nc->v4_configured))
			break;

		netconfig_remove_dhcp_address_routes(nc, true);
		nc->v4_configured = false;

		if (l_dhcp_client_start(nc->dhcp_client))
			/* TODO: also start a new timeout */
			netconfig_emit_event(nc, AF_INET,
						L_NETCONFIG_EVENT_UNCONFIGURE);
		else
			netconfig_emit_event(nc, AF_INET,
						L_NETCONFIG_EVENT_FAILED);

		break;
	case L_DHCP_CLIENT_EVENT_NO_LEASE:
		L_WARN_ON(nc->v4_configured);

		/*
		 * The requested address is no longer available, try to restart
		 * the client.
		 *
		 * TODO: this may need to be delayed so we don't flood the
		 * network with DISCOVERs and NAKs.  Also add a retry limit or
		 * better yet a configurable timeout.
		 */
		if (!l_dhcp_client_start(nc->dhcp_client))
			netconfig_emit_event(nc, AF_INET,
						L_NETCONFIG_EVENT_FAILED);

		break;
	}
}

static void netconfig_add_dhcp6_address(struct l_netconfig *nc)
{
	const struct l_dhcp6_lease *lease =
		l_dhcp6_client_get_lease(nc->dhcp6_client);
	_auto_(l_free) char *ip = NULL;
	uint32_t prefix_len;

	if (L_WARN_ON(!lease))
		return;

	ip = l_dhcp6_lease_get_address(lease);
	prefix_len = l_dhcp6_lease_get_prefix_length(lease);
	nc->v6_address = l_rtnl_address_new(ip, prefix_len);

	if (L_WARN_ON(!nc->v6_address))
		return;

	/*
	 * Assume we already have a route from a Router Advertisement
	 * covering the address from DHCPv6 + prefix length from DHCPv6.
	 * We might want to emit a warning of some sort or
	 * L_NETCONFIG_EVENT_FAILED if we don't since this would
	 * basically be fatal for IPv6 connectivity.
	 */
	l_rtnl_address_set_noprefixroute(nc->v6_address, true);

	l_queue_push_tail(nc->addresses.current, nc->v6_address);
	l_queue_push_tail(nc->addresses.added, nc->v6_address);
}

static void netconfig_set_dhcp6_address_lifetimes(struct l_netconfig *nc,
							bool updated)
{
	const struct l_dhcp6_lease *lease =
		l_dhcp6_client_get_lease(nc->dhcp6_client);
	uint32_t p, v;
	uint64_t start_time;

	if (L_WARN_ON(!lease))
		return;

	p = l_dhcp6_lease_get_preferred_lifetime(lease);
	v = l_dhcp6_lease_get_valid_lifetime(lease);
	start_time = l_dhcp6_lease_get_start_time(lease);

	l_rtnl_address_set_lifetimes(nc->v6_address, p, v);
	l_rtnl_address_set_expiry(nc->v6_address,
					start_time + p * L_USEC_PER_SEC,
					start_time + v * L_USEC_PER_SEC);

	if (updated && !netconfig_address_exists(nc->addresses.added,
							nc->v6_address))
		l_queue_push_tail(nc->addresses.updated, nc->v6_address);
}

static void netconfig_remove_dhcp6_address(struct l_netconfig *nc, bool expired)
{
	l_queue_remove(nc->addresses.current, nc->v6_address);
	l_queue_remove(nc->addresses.updated, nc->v6_address);

	if (!l_queue_remove(nc->addresses.added, nc->v6_address))
		l_queue_push_tail(
			expired ? nc->addresses.expired : nc->addresses.removed,
			nc->v6_address);

	nc->v6_address = NULL;
}

static void netconfig_dhcp6_event_handler(struct l_dhcp6_client *client,
						enum l_dhcp6_client_event event,
						void *user_data)
{
	struct l_netconfig *nc = user_data;

	switch (event) {
	case L_DHCP6_CLIENT_EVENT_LEASE_OBTAINED:
		if (L_WARN_ON(nc->v6_configured))
			break;

		netconfig_add_dhcp6_address(nc);
		netconfig_set_dhcp6_address_lifetimes(nc, false);
		nc->v6_configured = true;
		netconfig_emit_event(nc, AF_INET6, L_NETCONFIG_EVENT_CONFIGURE);
		break;
	case L_DHCP6_CLIENT_EVENT_IP_CHANGED:
		if (L_WARN_ON(!nc->v6_configured))
			break;

		netconfig_remove_dhcp6_address(nc, false);
		netconfig_add_dhcp6_address(nc);
		netconfig_set_dhcp6_address_lifetimes(nc, false);
		netconfig_emit_event(nc, AF_INET6, L_NETCONFIG_EVENT_UPDATE);
		break;
	case L_DHCP6_CLIENT_EVENT_LEASE_EXPIRED:
		if (L_WARN_ON(!nc->v6_configured))
			break;

		netconfig_remove_dhcp6_address(nc, true);
		nc->v6_configured = false;

		if (l_dhcp6_client_start(nc->dhcp6_client))
			/* TODO: also start a new timeout */
			netconfig_emit_event(nc, AF_INET6,
						L_NETCONFIG_EVENT_UNCONFIGURE);
		else
			netconfig_emit_event(nc, AF_INET6,
						L_NETCONFIG_EVENT_FAILED);

		break;
	case L_DHCP6_CLIENT_EVENT_LEASE_RENEWED:
		if (L_WARN_ON(!nc->v6_configured))
			break;

		netconfig_set_dhcp6_address_lifetimes(nc, true);
		netconfig_emit_event(nc, AF_INET6, L_NETCONFIG_EVENT_UPDATE);
		break;
	case L_DHCP6_CLIENT_EVENT_NO_LEASE:
		if (L_WARN_ON(nc->v6_configured))
			break;

		/*
		 * The requested address is no longer available, try to restart
		 * the client.
		 *
		 * TODO: this may need to be delayed so we don't flood the
		 * network with SOLICITs and DECLINEs.  Also add a retry limit
		 * or better yet a configurable timeout.
		 */
		if (!l_dhcp6_client_start(nc->dhcp6_client))
			netconfig_emit_event(nc, AF_INET6,
						L_NETCONFIG_EVENT_FAILED);

		break;
	}
}

static uint64_t now;

static bool netconfig_check_route_expired(void *data, void *user_data)
{
	struct l_netconfig *nc = user_data;
	struct netconfig_route_data *rd = data;

	if (!rd->kernel_expiry || now < rd->kernel_expiry)
		return false;

	/*
	 * Since we set lifetimes on the routes we submit to the kernel with
	 * RTM_NEWROUTE, we count on them being deleted automatically so no
	 * need to send an RTM_DELROUTE.  We signal the fact that the route
	 * expired to the user by having it on the expired list but there's
	 * nothing that the user needs to do with the routes on that list
	 * like they do with the added, updated and removed lists.
	 *
	 * If for some reason the route is still on the added list, drop it
	 * from there and there's nothing to notify the user of.
	 */
	if (!l_queue_remove(nc->routes.added, rd->route))
		l_queue_push_tail(nc->routes.expired, rd->route);

	l_queue_remove(nc->routes.current, rd->route);
	l_queue_remove(nc->routes.updated, rd->route);
	l_queue_remove(nc->routes.removed, rd->route);
	return true;
}

static void netconfig_expire_routes(struct l_netconfig *nc)
{
	now = l_time_now();

	if (l_queue_foreach_remove(nc->icmp_route_data,
					netconfig_check_route_expired, nc) &&
			!l_queue_isempty(nc->routes.expired) &&
			!nc->signal_expired_work)
		nc->signal_expired_work = l_idle_create(
						netconfig_signal_expired,
						nc, NULL);
}

static struct netconfig_route_data *netconfig_find_icmp6_route(
						struct l_netconfig *nc,
						const uint8_t *gateway,
						const struct route_info *dst)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(nc->icmp_route_data); entry;
			entry = entry->next) {
		struct netconfig_route_data *rd = entry->data;
		const uint8_t *route_gateway;
		const uint8_t *route_dst;
		uint8_t route_prefix_len = 0;

		route_gateway = l_rtnl_route_get_gateway_in_addr(rd->route);
		if ((gateway || route_gateway) &&
				(!gateway || !route_gateway ||
				 memcmp(gateway, route_gateway, 16)))
			continue;

		route_dst = l_rtnl_route_get_dst_in_addr(rd->route,
							&route_prefix_len);
		if ((dst || route_prefix_len) &&
				(!dst || !route_prefix_len ||
				 dst->prefix_len != route_prefix_len ||
				 memcmp(dst->address, route_dst, 16)))
			continue;

		return rd;
	}

	return NULL;
}

static struct netconfig_route_data *netconfig_add_icmp6_route(
						struct l_netconfig *nc,
						const uint8_t *gateway,
						const struct route_info *dst,
						uint8_t preference)
{
	struct netconfig_route_data *rd;
	struct l_rtnl_route *rt;

	rt = netconfig_route_new(nc, AF_INET6, dst ? dst->address : NULL,
					dst ? dst->prefix_len : 0, gateway,
					RTPROT_RA);
	if (L_WARN_ON(!rt))
		return NULL;

	l_rtnl_route_set_preference(rt, preference);
	l_queue_push_tail(nc->routes.current, rt);
	l_queue_push_tail(nc->routes.added, rt);

	rd = l_new(struct netconfig_route_data, 1);
	rd->route = rt;
	l_queue_push_tail(nc->icmp_route_data, rd);
	return rd;
}

static bool netconfig_check_route_need_update(
					const struct netconfig_route_data *rd,
					const struct l_icmp6_router *ra,
					uint64_t new_expiry,
					uint64_t old_expiry)
{
	/*
	 * Decide whether the route is close enough to its expiry time that,
	 * based on the expected Router Advertisement frequency, we should
	 * notify the user and have them update the route's lifetime in the
	 * kernel.  This is an optimization to avoid triggering a syscall and
	 * potentially multiple context-switches in case we expect to have
	 * many more opportunities to update the lifetime before we even get
	 * close to the last expiry time we passed to the kernel.  Without
	 * this we might be wasting a lot of cycles over time if the RAs are
	 * frequent.
	 *
	 * Always update if we have no RA interval information or if the
	 * expiry is moved forward.
	 */
	if (!rd->max_ra_interval || new_expiry < rd->kernel_expiry)
		return true;

	return rd->kernel_expiry < ra->start_time + rd->max_ra_interval * 10;
}

static void netconfig_set_icmp6_route_data(struct l_netconfig *nc,
						struct netconfig_route_data *rd,
						const struct l_icmp6_router *ra,
						uint32_t preferred_lifetime,
						uint32_t valid_lifetime,
						uint32_t mtu, bool updated)
{
	uint64_t expiry = ra->start_time + valid_lifetime * L_USEC_PER_SEC;
	uint64_t old_expiry = l_rtnl_route_get_expiry(rd->route);
	bool differs = false;

	if (mtu != l_rtnl_route_get_mtu(rd->route)) {
		l_rtnl_route_set_mtu(rd->route, mtu);
		differs = true;
	}

	/*
	 * The route's lifetime is pretty useless on its own but keep it
	 * updated with the value from the last RA.  Routers can send the same
	 * lifetime in every RA, keep decreasing the lifetimes linearly or
	 * implement any other policy, regardless of whether the resulting
	 * expiry time varies or not.
	 */
	l_rtnl_route_set_lifetime(rd->route, valid_lifetime);

	if (rd->last_ra_time) {
		uint64_t interval = ra->start_time - rd->last_ra_time;

		if (interval > rd->max_ra_interval)
			rd->max_ra_interval = interval;
	}

	rd->last_ra_time = ra->start_time;

	/*
	 * valid_lifetime of 0 from a route_info means the route is being
	 * removed so we wouldn't be here.  valid_lifetime of 0xffffffff
	 * means no timeout.  Check if the lifetime is changing between
	 * finite and infinite, or two finite values that result in expiry
	 * time difference of more than a second -- to avoid emitting
	 * updates for changes resulting only from the valid_lifetime one
	 * second resolution and RA transmission jitter.  As RFC4861
	 * Section 6.2.7 puts it: "Due to link propagation delays and
	 * potentially poorly synchronized clocks between the routers such
	 * comparison SHOULD allow some time skew."  The RFC talks about
	 * routers processing one another's RAs but the same logic applies
	 * here.
	 */
	if (valid_lifetime == 0xffffffff)
		expiry = 0;

	if ((expiry || old_expiry) &&
			(!expiry || !old_expiry ||
			 l_time_diff(expiry, old_expiry) > L_USEC_PER_SEC)) {
		l_rtnl_route_set_expiry(rd->route, expiry);

		differs = differs || !expiry || !old_expiry ||
			netconfig_check_route_need_update(rd, ra,
							expiry, old_expiry);
	}

	if (updated && differs && !netconfig_route_exists(nc->routes.added,
								rd->route)) {
		l_queue_push_tail(nc->routes.updated, rd->route);
		rd->kernel_expiry = expiry;
	}
}

static void netconfig_remove_icmp6_route(struct l_netconfig *nc,
						struct netconfig_route_data *rd)
{
	l_queue_remove(nc->icmp_route_data, rd);
	l_queue_remove(nc->routes.current, rd->route);
	l_queue_remove(nc->routes.updated, rd->route);

	if (!l_queue_remove(nc->routes.added, rd->route))
		l_queue_push_tail(nc->routes.removed, rd->route);
}

static void netconfig_icmp6_event_handler(struct l_icmp6_client *client,
						enum l_icmp6_client_event event,
						void *event_data,
						void *user_data)
{
	struct l_netconfig *nc = user_data;
	const struct l_icmp6_router *r;
	struct netconfig_route_data *default_rd;
	unsigned int i;

	if (event != L_ICMP6_CLIENT_EVENT_ROUTER_FOUND)
		return;

	r = event_data;

	/*
	 * Note: If this is the first RA received, the l_dhcp6_client
	 * will have received the event before us and will be acting
	 * on it by now.
	 */

	if (nc->v6_gateway_override)
		return;

	netconfig_expire_routes(nc);

	/* Process the default gateway information */
	default_rd = netconfig_find_icmp6_route(nc, r->address, NULL);

	if (!default_rd && r->lifetime) {
		default_rd = netconfig_add_icmp6_route(nc, r->address, NULL,
								r->pref);
		if (unlikely(!default_rd))
			return;

		/*
		 * r->lifetime is 16-bit only so there's no risk it gets
		 * confused for the special 0xffffffff value in
		 * netconfig_set_icmp6_route_data.
		 */
		netconfig_set_icmp6_route_data(nc, default_rd, r, r->lifetime,
						r->lifetime, r->mtu, false);
	} else if (default_rd && r->lifetime)
		netconfig_set_icmp6_route_data(nc, default_rd, r, r->lifetime,
						r->lifetime, r->mtu, true);
	else if (default_rd && !r->lifetime)
		netconfig_remove_icmp6_route(nc, default_rd);

	/*
	 * Process the onlink and offlink routes, from the Router
	 * Advertisement's Prefix Information options and Route
	 * Information options respectively.
	 */
	for (i = 0; i < r->n_routes; i++) {
		const struct route_info *info = &r->routes[i];
		const uint8_t *gateway = info->onlink ? NULL : r->address;
		struct netconfig_route_data *rd =
			netconfig_find_icmp6_route(nc, gateway, info);

		if (!rd && info->valid_lifetime) {
			rd = netconfig_add_icmp6_route(nc, gateway, info,
							info->preference);
			if (unlikely(!rd))
				continue;

			netconfig_set_icmp6_route_data(nc, rd, r,
						info->preferred_lifetime,
						info->valid_lifetime,
						gateway ? r->mtu : 0, false);
		} else if (rd && info->valid_lifetime)
			netconfig_set_icmp6_route_data(nc, rd, r,
						info->preferred_lifetime,
						info->valid_lifetime,
						gateway ? r->mtu : 0, true);
		else if (rd && !info->valid_lifetime)
			netconfig_remove_icmp6_route(nc, rd);
	}

	/*
	 * Note: we may be emitting this before L_NETCONFIG_EVENT_CONFIGURE.
	 * We should probably instead save the affected routes in separate
	 * lists and add them to the _CONFIGURE event, suppressing any _UPDATE
	 * events while nc->v6_configured is false.
	 */
	if (!l_queue_isempty(nc->routes.added) ||
			!l_queue_isempty(nc->routes.updated) ||
			!l_queue_isempty(nc->routes.removed) ||
			!l_queue_isempty(nc->routes.expired))
		netconfig_emit_event(nc, AF_INET6, L_NETCONFIG_EVENT_UPDATE);
}

static int netconfig_proc_write_ipv6_setting(struct l_netconfig *nc,
						const char *setting,
						const char *value)
{
	char ifname[IF_NAMESIZE];
	_auto_(l_free) char *filename = NULL;
	int fd;
	int r;

	if (unlikely(!if_indextoname(nc->ifindex, ifname)))
		return -errno;

	filename = l_strdup_printf("/proc/sys/net/ipv6/conf/%s/%s",
					ifname, setting);

	fd = L_TFR(open(filename, O_WRONLY));
	if (unlikely(fd < 0))
		return -errno;

	r = L_TFR(write(fd, value, strlen(value)));
	L_TFR(close(fd));
	return r;
}

LIB_EXPORT struct l_netconfig *l_netconfig_new(uint32_t ifindex)
{
	struct l_netconfig *nc;

	nc = l_new(struct l_netconfig, 1);
	nc->ifindex = ifindex;
	nc->v4_enabled = true;

	nc->addresses.current = l_queue_new();
	nc->addresses.added = l_queue_new();
	nc->addresses.updated = l_queue_new();
	nc->addresses.removed = l_queue_new();
	nc->routes.current = l_queue_new();
	nc->routes.added = l_queue_new();
	nc->routes.updated = l_queue_new();
	nc->routes.removed = l_queue_new();
	nc->icmp_route_data = l_queue_new();

	nc->dhcp_client = l_dhcp_client_new(ifindex);
	l_dhcp_client_set_event_handler(nc->dhcp_client,
					netconfig_dhcp_event_handler,
					nc, NULL);

	nc->dhcp6_client = l_dhcp6_client_new(ifindex);
	l_dhcp6_client_set_event_handler(nc->dhcp6_client,
					netconfig_dhcp6_event_handler,
					nc, NULL);

	nc->icmp6_client = l_dhcp6_client_get_icmp6(nc->dhcp6_client);
	l_icmp6_client_add_event_handler(nc->icmp6_client,
					netconfig_icmp6_event_handler,
					nc, NULL);

	/* Disable in-kernel autoconfiguration for the interface */
	netconfig_proc_write_ipv6_setting(nc, "accept_ra", "0");

	return nc;
}

LIB_EXPORT void l_netconfig_destroy(struct l_netconfig *netconfig)
{
	if (unlikely(!netconfig))
		return;

	l_netconfig_stop(netconfig);

	l_netconfig_set_static_addr(netconfig, AF_INET, NULL);
	l_netconfig_set_gateway_override(netconfig, AF_INET, NULL);
	l_netconfig_set_dns_override(netconfig, AF_INET, NULL);
	l_netconfig_set_domain_names_override(netconfig, AF_INET, NULL);
	l_netconfig_set_static_addr(netconfig, AF_INET6, NULL);
	l_netconfig_set_gateway_override(netconfig, AF_INET6, NULL);
	l_netconfig_set_dns_override(netconfig, AF_INET6, NULL);
	l_netconfig_set_domain_names_override(netconfig, AF_INET6, NULL);

	l_dhcp_client_destroy(netconfig->dhcp_client);
	l_dhcp6_client_destroy(netconfig->dhcp6_client);
	l_netconfig_set_event_handler(netconfig, NULL, NULL, NULL);
	l_queue_destroy(netconfig->addresses.current, NULL);
	l_queue_destroy(netconfig->addresses.added, NULL);
	l_queue_destroy(netconfig->addresses.updated, NULL);
	l_queue_destroy(netconfig->addresses.removed, NULL);
	l_queue_destroy(netconfig->routes.current, NULL);
	l_queue_destroy(netconfig->routes.added, NULL);
	l_queue_destroy(netconfig->routes.updated, NULL);
	l_queue_destroy(netconfig->routes.removed, NULL);
	l_queue_destroy(netconfig->icmp_route_data, NULL);
	l_free(netconfig);
}

/*
 * The following l_netconfig_set_* functions configure the l_netconfig's
 * client settings.  The setters can be called independently, without
 * following a specific order.  Most of the setters will not validate the
 * values passed, l_netconfig_start() will fail if settings are incorrect
 * or inconsistent between themselves, e.g. if the static local IP and
 * gateway IP are not in the same subnet.  Alternatively
 * l_netconfig_check_config() can be called at any point to validate the
 * current configuration.  The configuration can only be changed while
 * the l_netconfig state machine is stopped, i.e. before
 * l_netconfig_start() and after l_netconfig_stop().
 *
 * l_netconfig_set_hostname, l_netconfig_set_static_addr,
 * l_netconfig_set_gateway_override, l_netconfig_set_dns_override and
 * l_netconfig_set_domain_names_override can be passed NULL to unset a
 * value that had been set before (revert to auto).  This is why the
 * family parameter is needed even when it could otherwise be derived
 * from the new value that is passed.
 */
LIB_EXPORT bool l_netconfig_set_family_enabled(struct l_netconfig *netconfig,
						uint8_t family, bool enabled)
{
	if (unlikely(!netconfig || netconfig->started))
		return false;

	switch (family) {
	case AF_INET:
		netconfig->v4_enabled = enabled;
		return true;
	case AF_INET6:
		netconfig->v6_enabled = enabled;
		return true;
	}

	return false;
}

LIB_EXPORT bool l_netconfig_set_hostname(struct l_netconfig *netconfig,
						const char *hostname)
{
	if (unlikely(!netconfig || netconfig->started))
		return false;

	return l_dhcp_client_set_hostname(netconfig->dhcp_client, hostname);
}

LIB_EXPORT bool l_netconfig_set_route_priority(struct l_netconfig *netconfig,
						uint32_t priority)
{
	if (unlikely(!netconfig || netconfig->started))
		return false;

	netconfig->route_priority = priority;
	return true;
}

LIB_EXPORT bool l_netconfig_set_static_addr(struct l_netconfig *netconfig,
					uint8_t family,
					const struct l_rtnl_address *addr)
{
	struct l_rtnl_address **ptr;

	if (unlikely(!netconfig || netconfig->started))
		return false;

	if (addr && l_rtnl_address_get_family(addr) != family)
		return false;

	switch (family) {
	case AF_INET:
		ptr = &netconfig->v4_static_addr;
		break;
	case AF_INET6:
		ptr = &netconfig->v6_static_addr;
		break;
	default:
		return false;
	}

	l_rtnl_address_free(*ptr);
	*ptr = NULL;

	if (!addr)
		return true;

	*ptr = l_rtnl_address_clone(addr);
	l_rtnl_address_set_lifetimes(*ptr, 0, 0);
	l_rtnl_address_set_noprefixroute(*ptr, true);
	return true;
}

LIB_EXPORT bool l_netconfig_set_gateway_override(struct l_netconfig *netconfig,
							uint8_t family,
							const char *gateway_str)
{
	char **ptr;

	if (unlikely(!netconfig || netconfig->started))
		return false;

	switch (family) {
	case AF_INET:
		ptr = &netconfig->v4_gateway_override;
		break;
	case AF_INET6:
		ptr = &netconfig->v6_gateway_override;
		break;
	default:
		return false;
	}

	l_free(*ptr);
	*ptr = NULL;

	if (!gateway_str)
		return true;

	*ptr = l_strdup(gateway_str);
	return true;
}

LIB_EXPORT bool l_netconfig_set_dns_override(struct l_netconfig *netconfig,
						uint8_t family, char **dns_list)
{
	char ***ptr;

	if (unlikely(!netconfig || netconfig->started))
		return false;

	switch (family) {
	case AF_INET:
		ptr = &netconfig->v4_dns_override;
		break;
	case AF_INET6:
		ptr = &netconfig->v6_dns_override;
		break;
	default:
		return false;
	}

	l_strv_free(*ptr);
	*ptr = NULL;

	if (!dns_list)
		return true;

	*ptr = l_strv_copy(dns_list);
	return true;
}

LIB_EXPORT bool l_netconfig_set_domain_names_override(
						struct l_netconfig *netconfig,
						uint8_t family, char **names)
{
	char ***ptr;

	if (unlikely(!netconfig || netconfig->started))
		return false;

	switch (family) {
	case AF_INET:
		ptr = &netconfig->v4_domain_names_override;
		break;
	case AF_INET6:
		ptr = &netconfig->v6_domain_names_override;
		break;
	default:
		return false;
	}

	l_strv_free(*ptr);
	*ptr = NULL;

	if (!names)
		return true;

	*ptr = l_strv_copy(names);
	return true;
}

static bool netconfig_check_family_config(struct l_netconfig *nc,
						uint8_t family)
{
	struct l_rtnl_address *static_addr = (family == AF_INET) ?
		nc->v4_static_addr : nc->v6_static_addr;
	char *gateway_override = (family == AF_INET) ?
		nc->v4_gateway_override : nc->v6_gateway_override;
	char **dns_override = (family == AF_INET) ?
		nc->v4_dns_override : nc->v6_dns_override;
	unsigned int dns_num = 0;

	if (static_addr && family == AF_INET) {
		uint8_t prefix_len =
			l_rtnl_address_get_prefix_length(static_addr);

		if (prefix_len > 30)
			return false;
	}

	if (gateway_override) {
		union netconfig_addr gateway;

		if (inet_pton(family, gateway_override, &gateway) != 1)
			return false;
	}

	if (dns_override && (dns_num = l_strv_length(dns_override))) {
		unsigned int i;
		_auto_(l_free) union netconfig_addr *dns_list =
			l_new(union netconfig_addr, dns_num);

		for (i = 0; i < dns_num; i++)
			if (inet_pton(family, dns_override[i],
					&dns_list[i]) != 1)
				return false;
	}

	return true;
}

static bool netconfig_check_config(struct l_netconfig *nc)
{
	/* TODO: error reporting through a debug log handler or otherwise */

	return netconfig_check_family_config(nc, AF_INET) &&
		netconfig_check_family_config(nc, AF_INET6);
}

LIB_EXPORT bool l_netconfig_check_config(struct l_netconfig *netconfig)
{
	if (unlikely(!netconfig || netconfig->started))
		return false;

	return netconfig_check_config(netconfig);
}

static void netconfig_add_v4_static_address_routes(struct l_netconfig *nc)
{
	char ip[INET_ADDRSTRLEN];
	uint32_t prefix_len;

	nc->v4_address = l_rtnl_address_clone(nc->v4_static_addr);
	l_queue_push_tail(nc->addresses.current, nc->v4_address);
	l_queue_push_tail(nc->addresses.added, nc->v4_address);

	l_rtnl_address_get_address(nc->v4_static_addr, ip);
	prefix_len = l_rtnl_address_get_prefix_length(nc->v4_static_addr);
	netconfig_add_v4_routes(nc, ip, prefix_len, NULL, RTPROT_STATIC);
}

/*
 * Just mirror the IPv4 behaviour with static IPv6 configuration.  It would
 * be more logical to let the user choose between static IPv6 address and
 * DHCPv6, and, completely independently, choose between static routes
 * (if a static prefix length and/or gateway address is set) and ICMPv6.
 * Yet a mechanism identical with IPv4 is easier to understand for a typical
 * user so providing a static address just disables all automatic
 * configuration.
 */
static void netconfig_add_v6_static_address_routes(struct l_netconfig *nc)
{
	char ip[INET6_ADDRSTRLEN];
	uint32_t prefix_len;

	nc->v6_address = l_rtnl_address_clone(nc->v6_static_addr);
	l_queue_push_tail(nc->addresses.current, nc->v6_address);
	l_queue_push_tail(nc->addresses.added, nc->v6_address);

	l_rtnl_address_get_address(nc->v6_static_addr, ip);
	prefix_len = l_rtnl_address_get_prefix_length(nc->v6_static_addr);
	netconfig_add_v6_static_routes(nc, ip, prefix_len);
}

static void netconfig_do_static_config(struct l_idle *idle, void *user_data)
{
	struct l_netconfig *nc = user_data;

	l_idle_remove(l_steal_ptr(nc->do_static_work));

	if (nc->v4_static_addr && !nc->v4_configured) {
		netconfig_add_v4_static_address_routes(nc);
		nc->v4_configured = true;
		netconfig_emit_event(nc, AF_INET, L_NETCONFIG_EVENT_CONFIGURE);
	}

	if (nc->v6_static_addr && !nc->v6_configured) {
		netconfig_add_v6_static_address_routes(nc);
		nc->v6_configured = true;
		netconfig_emit_event(nc, AF_INET6, L_NETCONFIG_EVENT_CONFIGURE);
	}
}

static void netconfig_rtnl_unregister(void *user_data)
{
	struct l_netlink *rtnl = user_data;

	if (!addr_wait_list || !l_queue_isempty(addr_wait_list))
		return;

	l_queue_destroy(l_steal_ptr(addr_wait_list), NULL);
	l_netlink_unregister(rtnl, rtnl_id);
	rtnl_id = 0;
}

static void netconfig_addr_wait_unregister(struct l_netconfig *nc,
						bool in_notify)
{
	struct l_netlink *rtnl = l_rtnl_get();

	if (nc->ifaddr6_dump_cmd_id) {
		unsigned int cmd_id = nc->ifaddr6_dump_cmd_id;

		nc->ifaddr6_dump_cmd_id = 0;
		l_netlink_cancel(rtnl, cmd_id);
	}

	if (!l_queue_remove(addr_wait_list, nc))
		return;

	if (!l_queue_isempty(addr_wait_list))
		return;

	/* We can't do l_netlink_unregister() inside a notification */
	if (in_notify)
		l_idle_oneshot(netconfig_rtnl_unregister, rtnl, NULL);
	else
		netconfig_rtnl_unregister(rtnl);
}

static void netconfig_ifaddr_ipv6_added(struct l_netconfig *nc,
					const struct ifaddrmsg *ifa,
					uint32_t len)
{
	struct in6_addr in6;
	_auto_(l_free) char *ip = NULL;

	if (ifa->ifa_flags & IFA_F_TENTATIVE)
		return;

	if (!nc->started)
		return;

	l_rtnl_ifaddr6_extract(ifa, len, &ip);
	inet_pton(AF_INET6, ip, &in6);

	if (!IN6_IS_ADDR_LINKLOCAL(&in6))
		return;

	netconfig_addr_wait_unregister(nc, true);

	l_dhcp6_client_set_link_local_address(nc->dhcp6_client, ip);

	/*
	 * Only now that we have a link-local address start actual DHCPv6
	 * setup.
	 */
	if (l_dhcp6_client_start(nc->dhcp6_client))
		return;

	netconfig_emit_event(nc, AF_INET6, L_NETCONFIG_EVENT_FAILED);
}

static void netconfig_ifaddr_ipv6_notify(uint16_t type, const void *data,
						uint32_t len, void *user_data)
{
	const struct ifaddrmsg *ifa = data;
	uint32_t bytes = len - NLMSG_ALIGN(sizeof(struct ifaddrmsg));
	const struct l_queue_entry *entry, *next;

	switch (type) {
	case RTM_NEWADDR:
		/* Iterate safely since elements may be removed */
		for (entry = l_queue_get_entries(addr_wait_list); entry;
				entry = next) {
			struct l_netconfig *nc = entry->data;

			next = entry->next;

			if (ifa->ifa_index == nc->ifindex)
				netconfig_ifaddr_ipv6_added(nc, ifa, bytes);
		}

		break;
	}
}

static void netconfig_ifaddr_ipv6_dump_cb(int error, uint16_t type,
						const void *data, uint32_t len,
						void *user_data)
{
	struct l_netconfig *nc = user_data;

	if (!nc->ifaddr6_dump_cmd_id || !nc->started)
		return;

	if (error) {
		netconfig_addr_wait_unregister(nc, false);
		netconfig_emit_event(nc, AF_INET6, L_NETCONFIG_EVENT_FAILED);
		return;
	}

	if (type != RTM_NEWADDR)
		return;

	netconfig_ifaddr_ipv6_notify(type, data, len, user_data);
}

static void netconfig_ifaddr_ipv6_dump_done_cb(void *user_data)
{
	struct l_netconfig *nc = user_data;

	/*
	 * Handle the case of no link-local address having been found during
	 * the dump.  If nc->ifaddr6_dump_cmd_id is 0, we have found one or
	 * the dump is being cancelled.  Otherwise try disabing the
	 * "disable_ipv6" setting for the interface since it may have been
	 * enabled.  Also write "addr_gen_mode" which triggers regerating
	 * the link-local addresss on the interface in the kernel if it
	 * was previously removed.
	 */
	if (!nc->ifaddr6_dump_cmd_id || !nc->started)
		return;

	nc->ifaddr6_dump_cmd_id = 0;

	/* "do not generate a link-local address" */
	netconfig_proc_write_ipv6_setting(nc, "addr_gen_mode", "1");
	/* "generate address based on EUI64 (default)" */
	netconfig_proc_write_ipv6_setting(nc, "addr_gen_mode", "0");
	/* "enable IPv6 operation" */
	netconfig_proc_write_ipv6_setting(nc, "disable_ipv6", "0");

	/* TODO: save original values and reset in l_netconfig_stop() */
}

LIB_EXPORT bool l_netconfig_start(struct l_netconfig *netconfig)
{
	if (unlikely(!netconfig || netconfig->started))
		return false;

	if (!netconfig_check_config(netconfig))
		return false;

	if (!netconfig->v4_enabled)
		goto configure_ipv6;

	if (netconfig->v4_static_addr) {
		/*
		 * We're basically ready to configure the interface
		 * but do this in an idle callback.
		 */
		netconfig->do_static_work = l_idle_create(
						netconfig_do_static_config,
						netconfig, NULL);
		goto configure_ipv6;
	}

	if (!l_dhcp_client_start(netconfig->dhcp_client))
		return false;

configure_ipv6:
	if (!netconfig->v6_enabled)
		goto done;

	if (netconfig->v6_static_addr) {
		/*
		 * We're basically ready to configure the interface
		 * but do this in an idle callback.
		 */
		if (!netconfig->do_static_work)
			netconfig->do_static_work = l_idle_create(
						netconfig_do_static_config,
						netconfig, NULL);

		goto done;
	}

	/*
	 * We only care about being on addr_wait_list if we're waiting for
	 * the link-local address for DHCP6.  Add ourself to the list here
	 * before we start the dump, instead of after it ends, to eliminate
	 * the possibility of missing an RTM_NEWADDR between the end of
	 * the dump command and registering for the events.
	 */
	if (!addr_wait_list) {
		addr_wait_list = l_queue_new();

		rtnl_id = l_netlink_register(l_rtnl_get(), RTNLGRP_IPV6_IFADDR,
						netconfig_ifaddr_ipv6_notify,
						netconfig, NULL);
		if (!rtnl_id)
			goto unregister;
	}

	netconfig->ifaddr6_dump_cmd_id = l_rtnl_ifaddr6_dump(l_rtnl_get(),
					netconfig_ifaddr_ipv6_dump_cb,
					netconfig,
					netconfig_ifaddr_ipv6_dump_done_cb);
	if (!netconfig->ifaddr6_dump_cmd_id)
		goto unregister;

	l_queue_push_tail(addr_wait_list, netconfig);

done:
	netconfig->started = true;
	return true;

unregister:
	netconfig_addr_wait_unregister(netconfig, false);

	if (netconfig->v4_enabled) {
		if (netconfig->v4_static_addr)
			l_idle_remove(l_steal_ptr(netconfig->do_static_work));
		else
			l_dhcp_client_stop(netconfig->dhcp_client);
	}

	return false;
}

LIB_EXPORT void l_netconfig_stop(struct l_netconfig *netconfig)
{
	if (unlikely(!netconfig || !netconfig->started))
		return;

	netconfig->started = false;

	if (netconfig->do_static_work)
		l_idle_remove(l_steal_ptr(netconfig->do_static_work));

	if (netconfig->signal_expired_work)
		l_idle_remove(l_steal_ptr(netconfig->signal_expired_work));

	netconfig_addr_wait_unregister(netconfig, false);

	netconfig_update_cleanup(netconfig);
	l_queue_clear(netconfig->addresses.current,
			(l_queue_destroy_func_t) l_rtnl_address_free);
	l_queue_clear(netconfig->routes.current,
			(l_queue_destroy_func_t) l_rtnl_route_free);
	l_queue_clear(netconfig->icmp_route_data, l_free);
	netconfig->v4_address = NULL;
	netconfig->v4_subnet_route = NULL;
	netconfig->v4_default_route = NULL;
	netconfig->v6_address = NULL;
	netconfig->v4_configured = false;
	netconfig->v6_configured = false;

	l_dhcp_client_stop(netconfig->dhcp_client);
	l_dhcp6_client_stop(netconfig->dhcp6_client);
}

LIB_EXPORT struct l_dhcp_client *l_netconfig_get_dhcp_client(
						struct l_netconfig *netconfig)
{
	if (unlikely(!netconfig))
		return NULL;

	return netconfig->dhcp_client;
}

LIB_EXPORT struct l_dhcp6_client *l_netconfig_get_dhcp6_client(
						struct l_netconfig *netconfig)
{
	if (unlikely(!netconfig))
		return NULL;

	return netconfig->dhcp6_client;
}

LIB_EXPORT struct l_icmp6_client *l_netconfig_get_icmp6_client(
						struct l_netconfig *netconfig)
{
	if (unlikely(!netconfig))
		return NULL;

	return netconfig->icmp6_client;
}

LIB_EXPORT void l_netconfig_set_event_handler(struct l_netconfig *netconfig,
					l_netconfig_event_cb_t handler,
					void *user_data,
					l_netconfig_destroy_cb_t destroy)
{
	if (unlikely(!netconfig))
		return;

	if (netconfig->handler.destroy)
		netconfig->handler.destroy(netconfig->handler.user_data);

	netconfig->handler.callback = handler;
	netconfig->handler.user_data = user_data;
	netconfig->handler.destroy = destroy;
}

LIB_EXPORT void l_netconfig_apply_rtnl(struct l_netconfig *netconfig)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(netconfig->addresses.removed); entry;
			entry = entry->next)
		l_rtnl_ifaddr_delete(l_rtnl_get(), netconfig->ifindex,
					entry->data, NULL, NULL, NULL);

	for (entry = l_queue_get_entries(netconfig->addresses.added); entry;
			entry = entry->next)
		l_rtnl_ifaddr_add(l_rtnl_get(), netconfig->ifindex,
					entry->data, NULL, NULL, NULL);

	/* We can use l_rtnl_ifaddr_add here since that uses NLM_F_REPLACE */
	for (entry = l_queue_get_entries(netconfig->addresses.updated); entry;
			entry = entry->next)
		l_rtnl_ifaddr_add(l_rtnl_get(), netconfig->ifindex,
					entry->data, NULL, NULL, NULL);

	for (entry = l_queue_get_entries(netconfig->routes.removed); entry;
			entry = entry->next)
		l_rtnl_route_delete(l_rtnl_get(), netconfig->ifindex,
					entry->data, NULL, NULL, NULL);

	for (entry = l_queue_get_entries(netconfig->routes.added); entry;
			entry = entry->next)
		l_rtnl_route_add(l_rtnl_get(), netconfig->ifindex,
					entry->data, NULL, NULL, NULL);

	/* We can use l_rtnl_route_add here since that uses NLM_F_REPLACE */
	for (entry = l_queue_get_entries(netconfig->routes.updated); entry;
			entry = entry->next)
		l_rtnl_route_add(l_rtnl_get(), netconfig->ifindex,
					entry->data, NULL, NULL, NULL);
}

LIB_EXPORT const struct l_queue_entry *l_netconfig_get_addresses(
					struct l_netconfig *netconfig,
					const struct l_queue_entry **out_added,
					const struct l_queue_entry **out_updated,
					const struct l_queue_entry **out_removed,
					const struct l_queue_entry **out_expired)
{
	if (out_added)
		*out_added = l_queue_get_entries(netconfig->addresses.added);

	if (out_updated)
		*out_updated = l_queue_get_entries(netconfig->addresses.updated);

	if (out_removed)
		*out_removed = l_queue_get_entries(netconfig->addresses.removed);

	if (out_expired)
		*out_expired = l_queue_get_entries(netconfig->addresses.expired);

	return l_queue_get_entries(netconfig->addresses.current);
}

LIB_EXPORT const struct l_queue_entry *l_netconfig_get_routes(
					struct l_netconfig *netconfig,
					const struct l_queue_entry **out_added,
					const struct l_queue_entry **out_updated,
					const struct l_queue_entry **out_removed,
					const struct l_queue_entry **out_expired)
{
	netconfig_expire_routes(netconfig);

	if (out_added)
		*out_added = l_queue_get_entries(netconfig->routes.added);

	if (out_updated)
		*out_updated = l_queue_get_entries(netconfig->routes.updated);

	if (out_removed)
		*out_removed = l_queue_get_entries(netconfig->routes.removed);

	if (out_expired)
		*out_expired = l_queue_get_entries(netconfig->routes.expired);

	return l_queue_get_entries(netconfig->routes.current);
}

/*
 * Embedded Linux library
 * Copyright (C) 2018  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef __ELL_DHCP_H
#define __ELL_DHCP_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct l_dhcp_client;
struct l_dhcp_lease;
struct l_netlink;
struct l_dhcp_server;

/* RFC 2132 */
enum l_dhcp_option {
	L_DHCP_OPTION_SUBNET_MASK = 1, /* Section 3.3  */
	L_DHCP_OPTION_ROUTER = 3, /* Section 3.5 */
	L_DHCP_OPTION_DOMAIN_NAME_SERVER = 6, /* Section 3.8 */
	L_DHCP_OPTION_HOST_NAME = 12, /* Section 3.14 */
	L_DHCP_OPTION_DOMAIN_NAME = 15, /* Section 3.17 */
	L_DHCP_OPTION_BROADCAST_ADDRESS = 28, /* Section 5.3 */
	L_DHCP_OPTION_NTP_SERVERS = 42, /* Section 8.3 */
	L_DHCP_OPTION_REQUESTED_IP_ADDRESS = 50, /* Section 9.1 */
	L_DHCP_OPTION_IP_ADDRESS_LEASE_TIME = 51, /* Section 9.2 */
	L_DHCP_OPTION_RENEWAL_T1_TIME = 58, /* Section 9.11 */
	L_DHCP_OPTION_REBINDING_T2_TIME = 59, /* Section 9.12 */
	L_DHCP_OPTION_SERVER_IDENTIFIER = 54, /* Section 9.7 */
};

enum l_dhcp_client_event {
	L_DHCP_CLIENT_EVENT_LEASE_OBTAINED = 0,
	L_DHCP_CLIENT_EVENT_IP_CHANGED,
	L_DHCP_CLIENT_EVENT_LEASE_EXPIRED,
	L_DHCP_CLIENT_EVENT_LEASE_RENEWED,
	L_DHCP_CLIENT_EVENT_NO_LEASE,
	L_DHCP_CLIENT_EVENT_MAX_ATTEMPTS_REACHED,
};

enum l_dhcp_server_event {
	L_DHCP_SERVER_EVENT_NEW_LEASE,
	L_DHCP_SERVER_EVENT_LEASE_EXPIRED,
};

typedef void (*l_dhcp_client_event_cb_t)(struct l_dhcp_client *client,
						enum l_dhcp_client_event event,
						void *userdata);
typedef void (*l_dhcp_debug_cb_t)(const char *str, void *user_data);
typedef void (*l_dhcp_destroy_cb_t)(void *userdata);

typedef void (*l_dhcp_server_event_cb_t)(struct l_dhcp_server *server,
					enum l_dhcp_server_event event,
					void *user_data,
					const struct l_dhcp_lease *lease);

struct l_dhcp_client *l_dhcp_client_new(uint32_t ifindex);
bool l_dhcp_client_add_request_option(struct l_dhcp_client *client,
								uint8_t option);
void l_dhcp_client_destroy(struct l_dhcp_client *client);

bool l_dhcp_client_set_address(struct l_dhcp_client *client, uint8_t type,
					const uint8_t *addr, size_t addr_len);
bool l_dhcp_client_set_interface_name(struct l_dhcp_client *client,
							const char *ifname);
bool l_dhcp_client_set_hostname(struct l_dhcp_client *client,
							const char *hostname);

bool l_dhcp_client_set_rtnl(struct l_dhcp_client *client,
					struct l_netlink *rtnl);
bool l_dhcp_client_set_max_attempts(struct l_dhcp_client *client,
					uint8_t attempts);

const struct l_dhcp_lease *l_dhcp_client_get_lease(
					const struct l_dhcp_client *client);

bool l_dhcp_client_start(struct l_dhcp_client *client);
bool l_dhcp_client_stop(struct l_dhcp_client *client);

bool l_dhcp_client_set_event_handler(struct l_dhcp_client *client,
					l_dhcp_client_event_cb_t handler,
					void *userdata,
					l_dhcp_destroy_cb_t destroy);

bool l_dhcp_client_set_debug(struct l_dhcp_client *client,
				l_dhcp_debug_cb_t function,
				void *user_data, l_dhcp_destroy_cb_t destroy,
				int priority);


char *l_dhcp_lease_get_address(const struct l_dhcp_lease *lease);
uint32_t l_dhcp_lease_get_address_u32(const struct l_dhcp_lease *lease);
char *l_dhcp_lease_get_gateway(const struct l_dhcp_lease *lease);
uint32_t l_dhcp_lease_get_gateway_u32(const struct l_dhcp_lease *lease);
char *l_dhcp_lease_get_netmask(const struct l_dhcp_lease *lease);
uint32_t l_dhcp_lease_get_netmask_u32(const struct l_dhcp_lease *lease);
uint32_t l_dhcp_lease_get_prefix_length(const struct l_dhcp_lease *lease);
char *l_dhcp_lease_get_broadcast(const struct l_dhcp_lease *lease);
char *l_dhcp_lease_get_server_id(const struct l_dhcp_lease *lease);
const uint8_t *l_dhcp_lease_get_server_mac(const struct l_dhcp_lease *lease);
char **l_dhcp_lease_get_dns(const struct l_dhcp_lease *lease);
char *l_dhcp_lease_get_domain_name(const struct l_dhcp_lease *lease);
const uint8_t *l_dhcp_lease_get_mac(const struct l_dhcp_lease *lease);

uint32_t l_dhcp_lease_get_t1(const struct l_dhcp_lease *lease);
uint32_t l_dhcp_lease_get_t2(const struct l_dhcp_lease *lease);
uint32_t l_dhcp_lease_get_lifetime(const struct l_dhcp_lease *lease);
uint64_t l_dhcp_lease_get_start_time(const struct l_dhcp_lease *lease);

struct l_dhcp_server *l_dhcp_server_new(int ifindex);
void l_dhcp_server_destroy(struct l_dhcp_server *server);
bool l_dhcp_server_start(struct l_dhcp_server *server);
bool l_dhcp_server_stop(struct l_dhcp_server *server);
bool l_dhcp_server_set_ip_range(struct l_dhcp_server *server,
				const char *start_ip,
				const char *end_ip);
bool l_dhcp_server_set_debug(struct l_dhcp_server *server,
				l_dhcp_debug_cb_t function,
				void *user_data, l_dhcp_destroy_cb_t destroy);
bool l_dhcp_server_set_event_handler(struct l_dhcp_server *server,
					l_dhcp_server_event_cb_t handler,
					void *user_data,
					l_dhcp_destroy_cb_t destroy);
bool l_dhcp_server_set_lease_time(struct l_dhcp_server *server,
					unsigned int lease_time);
bool l_dhcp_server_set_interface_name(struct l_dhcp_server *server,
					const char *ifname);
bool l_dhcp_server_set_ip_address(struct l_dhcp_server *server,
						const char *ip);
bool l_dhcp_server_set_netmask(struct l_dhcp_server *server, const char *mask);
bool l_dhcp_server_set_gateway(struct l_dhcp_server *server, const char *ip);
bool l_dhcp_server_set_dns(struct l_dhcp_server *server, char **dns);
void l_dhcp_server_set_authoritative(struct l_dhcp_server *server,
					bool authoritative);
void l_dhcp_server_set_enable_rapid_commit(struct l_dhcp_server *server,
						bool enable);

struct l_dhcp_lease *l_dhcp_server_discover(struct l_dhcp_server *server,
						uint32_t requested_ip_opt,
						const uint8_t *client_id,
						const uint8_t *mac);
bool l_dhcp_server_request(struct l_dhcp_server *server,
				struct l_dhcp_lease *lease);
bool l_dhcp_server_decline(struct l_dhcp_server *server,
				struct l_dhcp_lease *lease);
bool l_dhcp_server_release(struct l_dhcp_server *server,
				struct l_dhcp_lease *lease);

bool l_dhcp_server_lease_remove(struct l_dhcp_server *server,
				struct l_dhcp_lease *lease);
void l_dhcp_server_expire_by_mac(struct l_dhcp_server *server,
					const uint8_t *mac);
#ifdef __cplusplus
}
#endif

#endif /* __ELL_DHCP_H */

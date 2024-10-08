/*
 * Embedded Linux library
 * Copyright (C) 2011-2014  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef __ELL_GENL_H
#define __ELL_GENL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct iovec;

struct l_genl;
struct l_genl_family_info;
struct l_genl_family;
struct l_genl_msg;

typedef void (*l_genl_destroy_func_t)(void *user_data);
typedef void (*l_genl_debug_func_t)(const char *str, void *user_data);
typedef void (*l_genl_msg_func_t)(struct l_genl_msg *msg, void *user_data);
typedef void (*l_genl_discover_func_t)(const struct l_genl_family_info *info,
						void *user_data);
typedef void (*l_genl_vanished_func_t)(const char *name, void *user_data);

struct l_genl *l_genl_new(void);
struct l_genl *l_genl_ref(struct l_genl *genl);
void l_genl_unref(struct l_genl *genl);

bool l_genl_set_debug(struct l_genl *genl, l_genl_debug_func_t callback,
				void *user_data, l_genl_destroy_func_t destroy);

bool l_genl_discover_families(struct l_genl *genl,
				l_genl_discover_func_t cb, void *user_data,
				l_genl_destroy_func_t destroy);

unsigned int l_genl_add_unicast_watch(struct l_genl *genl,
						const char *family,
						l_genl_msg_func_t handler,
						void *user_data,
						l_genl_destroy_func_t destroy);
bool l_genl_remove_unicast_watch(struct l_genl *genl, unsigned int id);

unsigned int l_genl_add_family_watch(struct l_genl *genl,
					const char *name,
					l_genl_discover_func_t appeared_func,
					l_genl_vanished_func_t vanished_func,
					void *user_data,
					l_genl_destroy_func_t destroy);
bool l_genl_remove_family_watch(struct l_genl *genl, unsigned int id);
bool l_genl_request_family(struct l_genl *genl, const char *name,
					l_genl_discover_func_t appeared_func,
					void *user_data,
					l_genl_destroy_func_t destroy);

struct l_genl_attr {
	const void *data;
	uint32_t len;
	const void *next_data;
	uint32_t next_len;
};

struct l_genl_msg* l_genl_msg_new(uint8_t cmd);
struct l_genl_msg *l_genl_msg_new_sized(uint8_t cmd, uint32_t size);
struct l_genl_msg *l_genl_msg_new_from_data(const void *data, size_t size);

const void *l_genl_msg_to_data(struct l_genl_msg *msg, uint16_t type,
				uint16_t flags, uint32_t seq, uint32_t pid,
				size_t *out_size);

struct l_genl_msg *l_genl_msg_ref(struct l_genl_msg *msg);
void l_genl_msg_unref(struct l_genl_msg *msg);

uint8_t l_genl_msg_get_command(struct l_genl_msg *msg);
uint8_t l_genl_msg_get_version(struct l_genl_msg *msg);
int l_genl_msg_get_error(struct l_genl_msg *msg);
const char *l_genl_msg_get_extended_error(struct l_genl_msg *msg);

bool l_genl_msg_append_attr(struct l_genl_msg *msg, uint16_t type,
					uint16_t len, const void *data);
bool l_genl_msg_append_attrv(struct l_genl_msg *msg, uint16_t type,
				const struct iovec *iov, size_t iov_len);
bool l_genl_msg_enter_nested(struct l_genl_msg *msg, uint16_t type);
bool l_genl_msg_leave_nested(struct l_genl_msg *msg);

bool l_genl_attr_init(struct l_genl_attr *attr, struct l_genl_msg *msg);

static inline bool l_genl_attr_next(struct l_genl_attr *attr, uint16_t *type,
					uint16_t *len, const void **data)
{
	return l_netlink_attr_next((struct l_netlink_attr *) attr,
					type, len, data) == 0;
}

static inline bool l_genl_attr_recurse(const struct l_genl_attr *attr,
				struct l_genl_attr *nested)
{
	return l_netlink_attr_recurse((struct l_netlink_attr *) attr,
					(struct l_netlink_attr *) nested) == 0;
}

bool l_genl_family_info_has_group(const struct l_genl_family_info *info,
					const char *group);
bool l_genl_family_info_can_send(const struct l_genl_family_info *info,
					uint8_t cmd);
bool l_genl_family_info_can_dump(const struct l_genl_family_info *info,
					uint8_t cmd);
char **l_genl_family_info_get_groups(const struct l_genl_family_info *info);
uint32_t l_genl_family_info_get_id(const struct l_genl_family_info *info);
const char *l_genl_family_info_get_name(const struct l_genl_family_info *info);
uint32_t l_genl_family_info_get_version(const struct l_genl_family_info *info);

struct l_genl_family *l_genl_family_new(struct l_genl *genl, const char *name);
void l_genl_family_free(struct l_genl_family *family);

const struct l_genl_family_info *l_genl_family_get_info(
						struct l_genl_family *family);

struct l_genl *l_genl_family_get_genl(struct l_genl_family *family);

unsigned int l_genl_family_send(struct l_genl_family *family,
				struct l_genl_msg *msg,
				l_genl_msg_func_t callback,
				void *user_data,
				l_genl_destroy_func_t destroy);
unsigned int l_genl_family_dump(struct l_genl_family *family,
				struct l_genl_msg *msg,
				l_genl_msg_func_t callback,
				void *user_data,
				l_genl_destroy_func_t destroy);
bool l_genl_family_cancel(struct l_genl_family *family, unsigned int id);
bool l_genl_family_request_sent(struct l_genl_family *family, unsigned int id);

unsigned int l_genl_family_register(struct l_genl_family *family,
				const char *group, l_genl_msg_func_t callback,
				void *user_data, l_genl_destroy_func_t destroy);
bool l_genl_family_unregister(struct l_genl_family *family, unsigned int id);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_GENL_H */

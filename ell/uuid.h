/*
 * Embedded Linux library
 * Copyright (C) 2011-2015  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef __ELL_UUID_H
#define __ELL_UUID_H

#include <stdbool.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

enum l_uuid_version {
	L_UUID_VERSION_1_TIME = 1,
	L_UUID_VERSION_2_DCE = 2,
	L_UUID_VERSION_3_MD5 = 3,
	L_UUID_VERSION_4_RANDOM = 4,
	L_UUID_VERSION_5_SHA1 = 5,
};

extern const uint8_t L_UUID_NAMESPACE_DNS[];
extern const uint8_t L_UUID_NAMESPACE_URL[];
extern const uint8_t L_UUID_NAMESPACE_OID[];
extern const uint8_t L_UUID_NAMESPACE_X500[];

bool l_uuid_v3(const uint8_t nsid[16], const void *name, size_t name_size,
			uint8_t out_uuid[16]);
bool l_uuid_v4(uint8_t out_uuid[16]);
bool l_uuid_v5(const uint8_t nsid[16], const void *name, size_t name_size,
			uint8_t out_uuid[16]);

bool l_uuid_is_valid(const uint8_t uuid[16]);
enum l_uuid_version l_uuid_get_version(const uint8_t uuid[16]);

bool l_uuid_to_string(const uint8_t uuid[16], char *dest, size_t dest_size);
bool l_uuid_from_string(const char *src, uint8_t uuid[16]);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_UTIL_H */

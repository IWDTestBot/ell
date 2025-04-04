/*
 * Embedded Linux library
 * Copyright (C) 2011-2014  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>

#include "useful.h"
#include "checksum.h"
#include "private.h"

#ifndef HAVE_LINUX_IF_ALG_H
#ifndef HAVE_LINUX_TYPES_H
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
#else
#include <linux/types.h>
#endif

#ifndef AF_ALG
#define AF_ALG	38
#define PF_ALG	AF_ALG
#endif

struct sockaddr_alg {
	__u16	salg_family;
	__u8	salg_type[14];
	__u32	salg_feat;
	__u32	salg_mask;
	__u8	salg_name[64];
};

/* Socket options */
#define ALG_SET_KEY	1

#else
#include <linux/if_alg.h>
#endif

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

struct checksum_info {
	const char *name;
	uint8_t digest_len;
	bool supported;
};

static struct checksum_info checksum_algs[] = {
	[L_CHECKSUM_MD4] = { .name = "md4", .digest_len = 16 },
	[L_CHECKSUM_MD5] = { .name = "md5", .digest_len = 16 },
	[L_CHECKSUM_SHA1] = { .name = "sha1", .digest_len = 20 },
	[L_CHECKSUM_SHA224] = { .name = "sha224", .digest_len = 28 },
	[L_CHECKSUM_SHA256] = { .name = "sha256", .digest_len = 32 },
	[L_CHECKSUM_SHA384] = { .name = "sha384", .digest_len = 48 },
	[L_CHECKSUM_SHA512] = { .name = "sha512", .digest_len = 64 },
	[L_CHECKSUM_SHA3_224] = { .name = "sha3-224", .digest_len = 28 },
	[L_CHECKSUM_SHA3_256] = { .name = "sha3-256", .digest_len = 32 },
	[L_CHECKSUM_SHA3_384] = { .name = "sha3-384", .digest_len = 48 },
	[L_CHECKSUM_SHA3_512] = { .name = "sha3-512", .digest_len = 64 },
};

static struct checksum_info checksum_cmac_aes_alg =
	{ .name = "cmac(aes)", .digest_len = 16 };

static struct checksum_info checksum_hmac_algs[] = {
	[L_CHECKSUM_MD4] = { .name = "hmac(md4)", .digest_len = 16 },
	[L_CHECKSUM_MD5] = { .name = "hmac(md5)", .digest_len = 16 },
	[L_CHECKSUM_SHA1] = { .name = "hmac(sha1)", .digest_len = 20 },
	[L_CHECKSUM_SHA224] = { .name = "hmac(sha224)", .digest_len = 28 },
	[L_CHECKSUM_SHA256] = { .name = "hmac(sha256)", .digest_len = 32 },
	[L_CHECKSUM_SHA384] = { .name = "hmac(sha384)", .digest_len = 48 },
	[L_CHECKSUM_SHA512] = { .name = "hmac(sha512)", .digest_len = 64 },
	[L_CHECKSUM_SHA3_224] = { .name = "hmac(sha3-224)", .digest_len = 28 },
	[L_CHECKSUM_SHA3_256] = { .name = "hmac(sha3-256)", .digest_len = 32 },
	[L_CHECKSUM_SHA3_384] = { .name = "hmac(sha3-384)", .digest_len = 48 },
	[L_CHECKSUM_SHA3_512] = { .name = "hmac(sha3-512)", .digest_len = 64 },
};

static const struct {
	struct checksum_info *list;
	size_t n;
} checksum_info_table[] = {
	{ checksum_algs, L_ARRAY_SIZE(checksum_algs) },
	{ &checksum_cmac_aes_alg, 1 },
	{ checksum_hmac_algs, L_ARRAY_SIZE(checksum_hmac_algs) },
	{}
};

/**
 * SECTION:checksum
 * @short_description: Checksum handling
 *
 * Checksum handling
 */

#define is_valid_index(array, i) ((i) >= 0 && (i) < L_ARRAY_SIZE(array))

/**
 * l_checksum:
 *
 * Opaque object representing the checksum.
 */
struct l_checksum {
	int sk;
	const struct checksum_info *alg_info;
};

static int create_alg(const char *alg)
{
	struct sockaddr_alg salg;
	int sk;

	sk = socket(PF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return -1;

	memset(&salg, 0, sizeof(salg));
	salg.salg_family = AF_ALG;
	strcpy((char *) salg.salg_type, "hash");
	strcpy((char *) salg.salg_name, alg);

	if (bind(sk, (struct sockaddr *) &salg, sizeof(salg)) < 0) {
		close(sk);
		return -1;
	}

	return sk;
}

static struct l_checksum *checksum_new_common(const char *alg, int sockopt,
						const void *data, size_t len,
						struct checksum_info *info)
{
	struct l_checksum *checksum;
	int fd;

	fd = create_alg(alg);
	if (fd < 0)
		return NULL;

	if (data) {
		if (setsockopt(fd, SOL_ALG, sockopt, data, len) < 0) {
			close(fd);
			return NULL;
		}
	}

	checksum = l_new(struct l_checksum, 1);
	checksum->sk = accept4(fd, NULL, 0, SOCK_CLOEXEC);
	close(fd);

	if (checksum->sk < 0) {
		l_free(checksum);
		return NULL;
	}

	checksum->alg_info = info;
	return checksum;
}

/**
 * l_checksum_new:
 * @type: checksum type
 *
 * Creates new #l_checksum, using the checksum algorithm @type.
 *
 * Returns: a newly allocated #l_checksum object.
 **/
LIB_EXPORT struct l_checksum *l_checksum_new(enum l_checksum_type type)
{
	if (!is_valid_index(checksum_algs, type) || !checksum_algs[type].name)
		return NULL;

	return checksum_new_common(checksum_algs[type].name, 0, NULL, 0,
					&checksum_algs[type]);
}

LIB_EXPORT struct l_checksum *l_checksum_new_cmac_aes(const void *key,
							size_t key_len)
{
	return checksum_new_common("cmac(aes)", ALG_SET_KEY, key, key_len,
					&checksum_cmac_aes_alg);
}

LIB_EXPORT struct l_checksum *l_checksum_new_hmac(enum l_checksum_type type,
					const void *key, size_t key_len)
{
	if (!is_valid_index(checksum_hmac_algs, type) ||
			!checksum_hmac_algs[type].name)
		return NULL;

	return checksum_new_common(checksum_hmac_algs[type].name,
					ALG_SET_KEY, key, key_len,
					&checksum_hmac_algs[type]);
}

/**
 * l_checksum_clone:
 * @checksum: parent checksum object
 *
 * Creates a new checksum with an independent copy of parent @checksum's
 * state.  l_checksum_get_digest can then be called on the parent or the
 * clone without affecting the state of the other object.
 **/
LIB_EXPORT struct l_checksum *l_checksum_clone(struct l_checksum *checksum)
{
	struct l_checksum *clone;

	if (unlikely(!checksum))
		return NULL;

	clone = l_new(struct l_checksum, 1);
	clone->sk = accept4(checksum->sk, NULL, 0, SOCK_CLOEXEC);

	if (clone->sk < 0) {
		l_free(clone);
		return NULL;
	}

	clone->alg_info = checksum->alg_info;
	return clone;
}

/**
 * l_checksum_free:
 * @checksum: checksum object
 *
 * Frees the memory allocated for @checksum.
 **/
LIB_EXPORT void l_checksum_free(struct l_checksum *checksum)
{
	if (unlikely(!checksum))
		return;

	close(checksum->sk);
	l_free(checksum);
}

/**
 * l_checksum_reset:
 * @checksum: checksum object
 *
 * Resets the internal state of @checksum.
 **/
LIB_EXPORT void l_checksum_reset(struct l_checksum *checksum)
{
	if (unlikely(!checksum))
		return;

	send(checksum->sk, NULL, 0, 0);
}

/**
 * l_checksum_update:
 * @checksum: checksum object
 * @data: data pointer
 * @len: length of data
 *
 * Updates checksum from @data pointer with @len bytes.
 *
 * Returns: true if the operation succeeded, false otherwise.
 **/
LIB_EXPORT bool l_checksum_update(struct l_checksum *checksum,
					const void *data, size_t len)
{
	ssize_t written;

	if (unlikely(!checksum))
		return false;

	written = send(checksum->sk, data, len, MSG_MORE);
	if (written < 0)
		return false;

	return true;
}

/**
 * l_checksum_updatev:
 * @checksum: checksum object
 * @iov: iovec pointer
 * @iov_len: Number of iovec entries
 *
 * This is a iovec based version of l_checksum_update; it updates the checksum
 * based on contents of @iov and @iov_len.
 *
 * Returns: true if the operation succeeded, false otherwise.
 **/
LIB_EXPORT bool l_checksum_updatev(struct l_checksum *checksum,
					const struct iovec *iov, size_t iov_len)
{
	struct msghdr msg;
	ssize_t written;

	if (unlikely(!checksum))
		return false;

	if (unlikely(!iov) || unlikely(!iov_len))
		return false;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = (struct iovec *) iov;
	msg.msg_iovlen = iov_len;

	written = sendmsg(checksum->sk, &msg, MSG_MORE);
	if (written < 0)
		return false;

	return true;
}

/**
 * l_checksum_get_digest:
 * @checksum: checksum object
 * @digest: output data buffer
 * @len: length of output buffer
 *
 * Writes the digest from @checksum as raw binary data into the provided
 * buffer or, if the buffer is shorter, the initial @len bytes of the digest
 * data.
 *
 * Returns: Number of bytes written, or negative value if an error occurred.
 **/
LIB_EXPORT ssize_t l_checksum_get_digest(struct l_checksum *checksum,
						void *digest, size_t len)
{
	ssize_t result;

	if (unlikely(!checksum))
		return -EINVAL;

	if (unlikely(!digest))
		return -EFAULT;

	if (unlikely(!len))
		return -EINVAL;

	result = recv(checksum->sk, digest, len, 0);
	if (result < 0)
		return -errno;

	if ((size_t) result < len && result < checksum->alg_info->digest_len)
		return -EIO;

	return result;
}

/**
 * l_checksum_get_string:
 * @checksum: checksum object
 *
 * Gets the digest from @checksum as hex encoded string.
 *
 * Returns: a newly allocated hex string
 **/
LIB_EXPORT char *l_checksum_get_string(struct l_checksum *checksum)
{
	unsigned char digest[64];

	if (unlikely(!checksum))
		return NULL;

	l_checksum_get_digest(checksum, digest, sizeof(digest));

	return l_util_hexstring(digest, checksum->alg_info->digest_len);
}

static void init_supported()
{
	static bool initialized = false;
	struct sockaddr_alg salg;
	int sk;
	unsigned int i, j;

	if (likely(initialized))
		return;

	initialized = true;

	sk = socket(PF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return;

	memset(&salg, 0, sizeof(salg));
	salg.salg_family = AF_ALG;
	strcpy((char *) salg.salg_type, "hash");

	for (i = 0; checksum_info_table[i].list; i++)
		for (j = 0; j < checksum_info_table[i].n; j++) {
			struct checksum_info *info;

			info = &checksum_info_table[i].list[j];
			if (!info->name)
				continue;

			strcpy((char *) salg.salg_name, info->name);

			if (bind(sk, (struct sockaddr *) &salg,
						sizeof(salg)) < 0)
				continue;

			info->supported = true;
		}

	close(sk);
}

LIB_EXPORT bool l_checksum_is_supported(enum l_checksum_type type,
							bool check_hmac)
{
	const struct checksum_info *list;

	init_supported();

	if (!check_hmac) {
		if (!is_valid_index(checksum_algs, type))
			return false;

		list = checksum_algs;
	} else {
		if (!is_valid_index(checksum_hmac_algs, type))
			return false;

		list = checksum_hmac_algs;
	}

	return list[type].supported;
}

LIB_EXPORT bool l_checksum_cmac_aes_supported()
{
	init_supported();

	return checksum_cmac_aes_alg.supported;
}

LIB_EXPORT ssize_t l_checksum_digest_length(enum l_checksum_type type)
{
	return is_valid_index(checksum_algs, type) ?
		checksum_algs[type].digest_len : 0;
}

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
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>

#include "utf8.h"
#include "util.h"
#include "useful.h"
#include "private.h"

/**
 * SECTION:util
 * @short_description: Utility functions
 *
 * Utility functions
 */

/**
 * l_malloc:
 * @size: memory size to allocate
 *
 * If for any reason the memory allocation fails, then execution will be
 * halted via abort().
 *
 * In case @size is 0 then #NULL will be returned.
 *
 * Returns: pointer to allocated memory
 **/
LIB_EXPORT void *l_malloc(size_t size)
{
	if (likely(size)) {
		void *ptr;

		ptr = malloc(size);
		if (ptr)
			return ptr;

		fprintf(stderr, "%s:%s(): failed to allocate %zd bytes\n",
					STRLOC, __func__, size);
		abort();
	}

	return NULL;
}

/**
 * l_realloc:
 * @mem: previously allocated memory, or NULL
 * @size: memory size to allocate
 *
 * If for any reason the memory allocation fails, then execution will be
 * halted via abort().
 *
 * In case @mem is NULL, this function acts like l_malloc.
 * In case @size is 0 then #NULL will be returned.
 *
 * Returns: pointer to allocated memory
 **/
LIB_EXPORT void *l_realloc(void *mem, size_t size)
{
	if (likely(size)) {
		void *ptr;

		ptr = realloc(mem, size);
		if (ptr)
			return ptr;

		fprintf(stderr, "%s:%s(): failed to re-allocate %zd bytes\n",
					STRLOC, __func__, size);
		abort();
	} else
		l_free(mem);

	return NULL;
}

/**
 * l_memdup:
 * @mem: pointer to memory you want to duplicate
 * @size: memory size
 *
 * If for any reason the memory allocation fails, then execution will be
 * halted via abort().
 *
 * In case @size is 0 then #NULL will be returned.
 *
 * Returns: pointer to duplicated memory buffer
 **/
LIB_EXPORT void *l_memdup(const void *mem, size_t size)
{
	void *ptr;

	ptr = l_malloc(size);

	memcpy(ptr, mem, size);

	return ptr;
}

/**
 * l_free:
 * @ptr: memory pointer
 *
 * Free the allocated memory area.
 **/
LIB_EXPORT void l_free(void *ptr)
{
	free(ptr);
}

/**
 * l_strdup:
 * @str: string pointer
 *
 * Allocates and duplicates string
 *
 * Returns: a newly allocated string
 **/
LIB_EXPORT char *l_strdup(const char *str)
{
	if (likely(str)) {
		char *tmp;

		tmp = strdup(str);
		if (tmp)
			return tmp;

		fprintf(stderr, "%s:%s(): failed to allocate string\n",
						STRLOC, __func__);
		abort();
	}

	return NULL;
}

/**
 * l_strndup:
 * @str: string pointer
 * @max: Maximum number of characters to copy
 *
 * Allocates and duplicates string.  If the string is longer than @max
 * characters, only @max are copied and a null terminating character
 * is added.
 *
 * Returns: a newly allocated string
 **/
LIB_EXPORT char *l_strndup(const char *str, size_t max)
{
	if (likely(str)) {
		char *tmp;

		tmp = strndup(str, max);
		if (tmp)
			return tmp;

		fprintf(stderr, "%s:%s(): failed to allocate string\n",
						STRLOC, __func__);
		abort();
	}

	return NULL;
}

/**
 * l_strdup_printf:
 * @format: string format
 * @...: parameters to insert into format string
 *
 * Returns: a newly allocated string
 **/
LIB_EXPORT char *l_strdup_printf(const char *format, ...)
{
	va_list args;
	char *str;
	int len;

	va_start(args, format);
	len = vasprintf(&str, format, args);
	va_end(args);

	if (len < 0) {
		fprintf(stderr, "%s:%s(): failed to allocate string\n",
					STRLOC, __func__);
		abort();

		return NULL;
	}

	return str;
}

/**
 * l_strdup_vprintf:
 * @format: string format
 * @args: parameters to insert into format string
 *
 * Returns: a newly allocated string
 **/
LIB_EXPORT char *l_strdup_vprintf(const char *format, va_list args)
{
	char *str;
	int len;

	len = vasprintf(&str, format, args);

	if (len < 0) {
		fprintf(stderr, "%s:%s(): failed to allocate string\n",
					STRLOC, __func__);
		abort();

		return NULL;
	}

	return str;
}

/**
 * l_strlcpy:
 * @dst: Destination buffer for string
 * @src: Source buffer containing null-terminated string to copy
 * @len: Maximum destination buffer space to use
 *
 * Copies a string from the @src buffer to the @dst buffer, using no
 * more than @len bytes in @dst. @dst is guaranteed to be
 * null-terminated. The caller can determine if the copy was truncated by
 * checking if the return value is greater than or equal to @len.
 *
 * NOTE: Passing in a NULL string results in a no-op
 *
 * Returns: The length of the @src string, not including the null
 * terminator.
 */
LIB_EXPORT size_t l_strlcpy(char *dst, const char *src, size_t len)
{
	size_t src_len = src ? strlen(src) : 0;

	if (!src)
		goto done;

	if (len) {
		if (src_len < len) {
			len = src_len + 1;
		} else {
			len -= 1;
			dst[len] = '\0';
		}

		memcpy(dst, src, len);
	}

done:
	return src_len;
}

/**
 * l_str_has_prefix:
 * @str: A string to be examined
 * @delim: Prefix string
 *
 * Determines if the string given by @str is prefixed by string given by
 * @prefix.
 *
 * Returns: True if @str was prefixed by @prefix.  False otherwise.
 */
LIB_EXPORT bool l_str_has_prefix(const char *str, const char *prefix)
{
	size_t str_len;
	size_t prefix_len;

	if (unlikely(!str))
		return false;

	if (unlikely(!prefix))
		return false;

	str_len = strlen(str);
	prefix_len = strlen(prefix);

	if (str_len < prefix_len)
		return false;

	return !strncmp(str, prefix, prefix_len);
}

/**
 * l_str_has_suffix:
 * @str: A string to be examined
 * @suffix: Suffix string
 *
 * Determines if the string given by @str ends with the specified @suffix.
 *
 * Returns: True if @str ends with the specified @suffix.  False otherwise.
 */
LIB_EXPORT bool l_str_has_suffix(const char *str, const char *suffix)
{
	size_t str_len;
	size_t suffix_len;
	size_t len_diff;

	if (unlikely(!str))
		return false;

	if (unlikely(!suffix))
		return false;

	str_len = strlen(str);
	suffix_len = strlen(suffix);

	if (str_len < suffix_len)
		return false;

	len_diff = str_len - suffix_len;

	return !strcmp(&str[len_diff], suffix);
}

/**
 * l_streq0:
 * @a: First operand
 * @b: Second operand
 *
 * Returns: True if @a and @b are both NULL or both non-NULL and identical
 * according to strcmp.  False otherwise.
 */
LIB_EXPORT bool l_streq0(const char *a, const char *b)
{
	return a == b || (a && b && !strcmp(a, b));
}

/**
 * l_util_oidstring:
 * @buf: buffer pointer
 * @len: length of buffer
 *
 * Returns: a newly allocated string for OID in numeric representation.
 * In case of error, Null is returned.
 **/
LIB_EXPORT char *l_util_oidstring(const void *buf, size_t len)
{
	const unsigned char *ptr = buf;
	char *str;
	size_t str_len;
	size_t str_max;
	size_t i;

	if (unlikely(!buf) || unlikely(len < 2))
		return NULL;

	/* A very simple initial estimation */
	str_max = 4 + (len - 1) * 2;
	str = l_malloc(str_max);

	str_len = snprintf(str, str_max, "%u.%u", ptr[0] / 40, ptr[0] % 40);

	/* In the unlikely case the initial buffer is too small */
	if (unlikely(str_len >= str_max)) {
		str_max = str_len + 1;
		str = l_realloc(str, str_max);
		str_len = sprintf(str, "%u.%u", ptr[0] / 40, ptr[0] % 40);
	}

	i = 1;

	while (i < len) {
		unsigned long value = 0;
		unsigned char byte;
		size_t have_space;
		size_t l;

		do {
			/*
			 * Shift the current value by 7 bits to make room
			 * for the lower 7 bits of the byte in the stream.
			 */
			byte = ptr[i++];
			value = (value << 7) | (byte & 0x7F);

			/* This is a malformed OID */
			if (i > len) {
				l_free(str);
				return NULL;
			}
		} while (byte & 0x80);

		have_space = str_max - str_len;
		l = snprintf(str + str_len, have_space, ".%lu", value);

		if (l >= have_space) {
			str_max = str_len + l + 1;
			str = l_realloc(str, str_max);
			l = sprintf(str + str_len, ".%lu", value);
		}

		str_len += l;
	}

	return str;
}

static char *hexstring_common(const unsigned char *buf, size_t len,
				const char hexdigits[static 16])
{
	char *str;
	size_t i;

	if (unlikely(!buf) || unlikely(!len))
		return NULL;

	str = l_malloc(len * 2 + 1);

	for (i = 0; i < len; i++) {
		str[(i * 2) + 0] = hexdigits[buf[i] >> 4];
		str[(i * 2) + 1] = hexdigits[buf[i] & 0xf];
	}

	str[len * 2] = '\0';

	return str;
}

static char *hexstringv_common(const struct iovec *iov, size_t n_iov,
				const char hexdigits[static 16])
{
	char *str;
	size_t i, j, c;
	size_t len;

	if (unlikely(!iov || !n_iov))
		return NULL;

	for (i = 0, len = 0; i < n_iov; i++)
		len += iov[i].iov_len;

	str = l_malloc(len * 2 + 1);
	c = 0;

	for (i = 0; i < n_iov; i++) {
		const uint8_t *buf = iov[i].iov_base;

		for (j = 0; j < iov[i].iov_len; j++) {
			str[c++] = hexdigits[buf[j] >> 4];
			str[c++] = hexdigits[buf[j] & 0xf];
		}
	}

	str[len * 2] = '\0';

	return str;
}

/**
 * l_util_hexstring:
 * @buf: buffer pointer
 * @len: length of buffer
 *
 * Returns: a newly allocated hex string.  Note that the string will contain
 * lower case hex digits a-f.  If you require upper case hex digits, use
 * @l_util_hexstring_upper
 **/
LIB_EXPORT char *l_util_hexstring(const void *buf, size_t len)
{
	static const char hexdigits[] = "0123456789abcdef";
	return hexstring_common(buf, len, hexdigits);
}

/**
 * l_util_hexstring_upper:
 * @buf: buffer pointer
 * @len: length of buffer
 *
 * Returns: a newly allocated hex string.  Note that the string will contain
 * upper case hex digits a-f.  If you require lower case hex digits, use
 * @l_util_hexstring
 **/
LIB_EXPORT char *l_util_hexstring_upper(const void *buf, size_t len)
{
	static const char hexdigits[] = "0123456789ABCDEF";
	return hexstring_common(buf, len, hexdigits);
}

/**
 * l_util_hexstringv:
 * @iov: iovec
 * @n_iov: length of the iovec
 *
 * Returns: a newly allocated hex string.  Note that the string will contain
 * lower case hex digits a-f.  If you require upper case hex digits, use
 * @l_util_hexstringv_upper
 **/
LIB_EXPORT char *l_util_hexstringv(const struct iovec *iov, size_t n_iov)
{
	static const char hexdigits[] = "0123456789abcdef";
	return hexstringv_common(iov, n_iov, hexdigits);
}

/**
 * l_util_hexstringv_upper:
 * @iov: iovec
 * @n_iov: length of the iovec
 *
 * Returns: a newly allocated hex string.  Note that the string will contain
 * upper case hex digits a-f.  If you require lower case hex digits, use
 * @l_util_hexstringv
 **/
LIB_EXPORT char *l_util_hexstringv_upper(const struct iovec *iov, size_t n_iov)
{
	static const char hexdigits[] = "0123456789ABCDEF";
	return hexstringv_common(iov, n_iov, hexdigits);
}

/**
 * l_util_from_hexstring:
 * @str: Null-terminated string containing the hex-encoded bytes
 * @out_len: Number of bytes decoded
 *
 * Returns: a newly allocated byte array.  Empty strings are treated as
 * an error condition.
 **/
LIB_EXPORT unsigned char *l_util_from_hexstring(const char *str,
							size_t *out_len)
{
	size_t i, j;
	size_t len;
	char c;
	unsigned char *buf;

	if (unlikely(!str))
		return NULL;

	for (i = 0; str[i]; i++) {
		c = str[i];

		if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') ||
				(c >= 'a' && c <= 'f'))
			continue;

		return NULL;
	}

	if (!i)
		return NULL;

	if ((i % 2) != 0)
		return NULL;

	len = i;
	buf = l_malloc(i >> 1);

	for (i = 0, j = 0; i < len; i++, j++) {
		c = str[i];

		if (c >= '0' && c <= '9')
			buf[j] = c - '0';
		else if (c >= 'A' && c <= 'F')
			buf[j] = 10 + c - 'A';
		else if (c >= 'a' && c <= 'f')
			buf[j] = 10 + c - 'a';

		i += 1;
		c = str[i];

		if (c >= '0' && c <= '9')
			buf[j] = buf[j] * 16 + c - '0';
		else if (c >= 'A' && c <= 'F')
			buf[j] = buf[j] * 16 + 10 + c - 'A';
		else if (c >= 'a' && c <= 'f')
			buf[j] = buf[j] * 16 + 10 + c - 'a';
	}

	if (out_len)
		*out_len = j;

	return buf;
}

static void hexdump(const char dir, const unsigned char *buf, size_t len,
			l_util_hexdump_func_t function, void *user_data)
{
	static const char hexdigits[] = "0123456789abcdef";
	char str[68];
	size_t i;

	if (unlikely(!len))
		return;

	str[0] = dir;

	for (i = 0; i < len; i++) {
		str[((i % 16) * 3) + 1] = ' ';
		str[((i % 16) * 3) + 2] = hexdigits[buf[i] >> 4];
		str[((i % 16) * 3) + 3] = hexdigits[buf[i] & 0xf];
		str[(i % 16) + 51] = l_ascii_isprint(buf[i]) ? buf[i] : '.';

		if ((i + 1) % 16 == 0) {
			str[49] = ' ';
			str[50] = ' ';
			str[67] = '\0';
			function(str, user_data);
			str[0] = ' ';
		}
	}

	if (i % 16 > 0) {
		size_t j;
		for (j = (i % 16); j < 16; j++) {
			str[(j * 3) + 1] = ' ';
			str[(j * 3) + 2] = ' ';
			str[(j * 3) + 3] = ' ';
			str[j + 51] = ' ';
		}
		str[49] = ' ';
		str[50] = ' ';
		str[67] = '\0';
		function(str, user_data);
	}
}

LIB_EXPORT void l_util_hexdump(bool in, const void *buf, size_t len,
			l_util_hexdump_func_t function, void *user_data)
{
	if (likely(!function))
		return;

	hexdump(in ? '<' : '>', buf, len, function, user_data);
}

LIB_EXPORT void l_util_hexdump_two(bool in, const void *buf1, size_t len1,
			const void *buf2, size_t len2,
			l_util_hexdump_func_t function, void *user_data)
{
	if (likely(!function))
		return;

	hexdump(in ? '<' : '>', buf1, len1, function, user_data);
	hexdump(' ', buf2, len2, function, user_data);
}

LIB_EXPORT void l_util_hexdumpv(bool in, const struct iovec *iov,
					size_t n_iov,
					l_util_hexdump_func_t function,
					void *user_data)
{
	static const char hexdigits[] = "0123456789abcdef";
	char str[68];
	size_t i;
	size_t len;
	size_t c;
	const uint8_t *buf;

	if (likely(!function))
		return;

	if (unlikely(!iov || !n_iov))
		return;

	str[0] = in ? '<' : '>';

	for (i = 0, len = 0; i < n_iov; i++)
		len += iov[i].iov_len;

	c = 0;
	buf = iov[0].iov_base;

	for (i = 0; i < len; i++, c++) {
		if (c == iov[0].iov_len) {
			c = 0;
			iov += 1;
			buf = iov[0].iov_base;
		}

		str[((i % 16) * 3) + 1] = ' ';
		str[((i % 16) * 3) + 2] = hexdigits[buf[c] >> 4];
		str[((i % 16) * 3) + 3] = hexdigits[buf[c] & 0xf];
		str[(i % 16) + 51] = l_ascii_isprint(buf[c]) ? buf[c] : '.';

		if ((i + 1) % 16 == 0) {
			str[49] = ' ';
			str[50] = ' ';
			str[67] = '\0';
			function(str, user_data);
			str[0] = ' ';
		}
	}

	if (i % 16 > 0) {
		size_t j;
		for (j = (i % 16); j < 16; j++) {
			str[(j * 3) + 1] = ' ';
			str[(j * 3) + 2] = ' ';
			str[(j * 3) + 3] = ' ';
			str[j + 51] = ' ';
		}
		str[49] = ' ';
		str[50] = ' ';
		str[67] = '\0';
		function(str, user_data);
	}
}

LIB_EXPORT void l_util_debug(l_util_hexdump_func_t function, void *user_data,
						const char *format, ...)
{
	va_list args;
	char *str;
	int len;

	if (likely(!function))
		return;

	if (unlikely(!format))
		return;

	va_start(args, format);
	len = vasprintf(&str, format, args);
	va_end(args);

	if (unlikely(len < 0))
		return;

	function(str, user_data);

	free(str);
}

/**
 * l_util_get_debugfs_path:
 *
 * Returns: a pointer to mount point of debugfs
 **/
LIB_EXPORT const char *l_util_get_debugfs_path(void)
{
	static char path[PATH_MAX + 1];
	static bool found = false;
	char type[100];
	FILE *fp;

	if (found)
		return path;

	fp = fopen("/proc/mounts", "r");
	if (!fp)
		return NULL;

	while (fscanf(fp, "%*s %" L_STRINGIFY(PATH_MAX) "s %99s %*s %*d %*d\n",
							path, type) == 2) {
		if (!strcmp(type, "debugfs")) {
			found = true;
			break;
		}
	}

	fclose(fp);

	if (!found)
		return NULL;

	return path;
}

LIB_EXPORT bool l_memeq(const void *field, size_t size, uint8_t byte)
{
	const uint8_t *mem = field;
	size_t i;

	for (i = 0; i < size; i++)
		if (mem[i] != byte)
			return false;

	return true;
}

__attribute__((noinline)) static int __secure_memeq(const void *field,
						size_t size, uint8_t byte)
{
	unsigned int diff = 0;
	size_t i;

	for (i = 0; i < size; i++) {
		diff |= ((uint8_t *) field)[i] ^ byte;
		DO_NOT_OPTIMIZE(diff);
	}

	return diff;
}

LIB_EXPORT bool l_secure_memeq(const void *field, size_t size, uint8_t byte)
{
	return __secure_memeq(field, size, byte) == 0 ? true : false;
}

static int safe_atou(const char *s, int base, unsigned int *out_u)
{
	unsigned long int r;
	unsigned int t;
	char *endp;

	errno = 0;

	t = r = strtoul(s, &endp, base);
	if (unlikely(errno > 0))
		return -errno;

	if (endp == s || *endp != '\0')
		return -EINVAL;

	if (unlikely(r != t))
		return -ERANGE;

	if (out_u)
		*out_u = t;

	return 0;
}

LIB_EXPORT int l_safe_atou32(const char *s, uint32_t *out_u)
{
	if (unlikely(!s))
		return -EINVAL;

	if (!l_ascii_isdigit(s[0]))
		return -EINVAL;

	/* Don't allow leading zeros */
	if (s[0] == '0' && s[1] != '\0')
		return -EINVAL;

	return safe_atou(s, 10, out_u);
}

LIB_EXPORT int l_safe_atox8(const char *s, uint8_t *out_x)
{
	uint32_t x;
	int r;

	r = l_safe_atox32(s, &x);
	if (r < 0)
		return r;

	if (x > UINT8_MAX)
		return -ERANGE;

	if (out_x)
		*out_x = x;

	return 0;
}

LIB_EXPORT int l_safe_atox16(const char *s, uint16_t *out_x)
{
	uint32_t x;
	int r;

	r = l_safe_atox32(s, &x);
	if (r < 0)
		return r;

	if (x > UINT16_MAX)
		return -ERANGE;

	if (out_x)
		*out_x = x;

	return 0;
}

LIB_EXPORT int l_safe_atox32(const char *s, uint32_t *out_x)
{
	if (unlikely(!s))
		return -EINVAL;

	if (!l_ascii_isxdigit(s[0]))
		return -EINVAL;

	return safe_atou(s, 16, out_x);
}

LIB_EXPORT size_t l_util_pagesize(void)
{
	static size_t page_size = 0;

	if (likely(page_size > 0))
		return page_size;

	page_size = sysconf(_SC_PAGESIZE);
	return page_size;
}

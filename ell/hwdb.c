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
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <alloca.h>
#include <fnmatch.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "util.h"
#include "hwdb.h"
#include "private.h"

static const char trie_sig[8] = { 'K', 'S', 'L', 'P', 'H', 'H', 'R', 'H' };

struct trie_header {
	uint8_t  signature[8];		/* Signature */
	uint64_t tool_version;		/* Version of creator tool */
	uint64_t file_size;		/* Size of complete file */
	uint64_t header_size;		/* Size of header structure */
	uint64_t node_size;		/* Size of node structure */
	uint64_t child_size;		/* Size of child structure */
	uint64_t entry_size;		/* Size of entry structure */
	uint64_t root_offset;		/* Location of root node structure */
	uint64_t nodes_size;		/* Size of the nodes section */
	uint64_t strings_size;		/* Size of the strings section */

	/* followed by nodes_size nodes data */
	/* followed by strings_size strings data */
} __attribute__ ((packed));

struct trie_node {
	uint64_t prefix_offset;		/* Location of prefix string */
	uint8_t  child_count;		/* Number of child structures */
	uint8_t  padding[7];
	uint64_t entry_count;		/* Number of entry structures */

	/* followed by child_count child structures */
	/* followed by entry_count entry structures */
} __attribute__ ((packed));

struct trie_child {
	uint8_t  c;			/* Prefix character of child node */
	uint8_t  padding[7];
	uint64_t child_offset;		/* Location of child node structure */
} __attribute__ ((packed));

struct trie_entry {
	uint64_t key_offset;		/* Location of key string */
	uint64_t value_offset;		/* Location of value string */
} __attribute__ ((packed));

struct trie_entry_v2 {
	uint64_t key_offset;		/* Location of key string */
	uint64_t value_offset;		/* Location of value string */
	uint64_t filename_offset;
	uint64_t line_number;
} __attribute__ ((packed));

struct trie_entry_v3 {
	uint64_t key_offset;		/* Location of key string */
	uint64_t value_offset;		/* Location of value string */
	uint64_t filename_offset;
	uint32_t line_number;
	uint16_t file_priority;
	uint16_t padding;
} __attribute__ ((packed));

struct l_hwdb {
	int ref_count;
	int fd;
	time_t mtime;
	size_t size;
	void *addr;
	uint64_t node_size;
	uint64_t child_size;
	uint64_t entry_size;
	uint64_t root_offset;
};

LIB_EXPORT struct l_hwdb *l_hwdb_new(const char *pathname)
{
	struct trie_header *hdr;
	struct l_hwdb *hwdb;
	struct stat st;
	void *addr;
	size_t size;
	int fd;

	if (!pathname)
		return NULL;

	fd = open(pathname, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;

	if (fstat(fd, &st) < 0) {
		close(fd);
		return NULL;
	}

	size = st.st_size;
	if (size < sizeof(struct trie_header)) {
		close(fd);
		return NULL;
	}

	addr = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		close(fd);
		return NULL;
	}

	hdr = addr;
	if (memcmp(hdr->signature, trie_sig, sizeof(trie_sig)))
		goto failed;

	if (L_LE64_TO_CPU(hdr->file_size) != size)
		goto failed;

	if (L_LE64_TO_CPU(hdr->header_size) != sizeof(struct trie_header))
		goto failed;

	if (L_LE64_TO_CPU(hdr->node_size) != sizeof(struct trie_node))
		goto failed;

	if (L_LE64_TO_CPU(hdr->child_size) != sizeof(struct trie_child))
		goto failed;

	if (L_LE64_TO_CPU(hdr->entry_size) < sizeof(struct trie_entry))
		goto failed;

	if (L_LE64_TO_CPU(hdr->header_size) + L_LE64_TO_CPU(hdr->nodes_size) +
				L_LE64_TO_CPU(hdr->strings_size) != size)
		goto failed;

	hwdb = l_new(struct l_hwdb, 1);

	hwdb->fd = fd;
	hwdb->mtime = st.st_mtime;
	hwdb->size = size;
	hwdb->addr = addr;
	hwdb->node_size = L_LE64_TO_CPU(hdr->node_size);
	hwdb->child_size = L_LE64_TO_CPU(hdr->child_size);
	hwdb->entry_size = L_LE64_TO_CPU(hdr->entry_size);
	hwdb->root_offset = L_LE64_TO_CPU(hdr->root_offset);

	return l_hwdb_ref(hwdb);

failed:
	munmap(addr, st.st_size);
	close(fd);
	return NULL;
}

LIB_EXPORT struct l_hwdb *l_hwdb_new_default(void)
{
	struct l_hwdb *db = NULL;
	size_t i;
	static const char * const paths[] = {
		"/etc/systemd/hwdb/hwdb.bin",
		"/etc/udev/hwdb.bin",
		"/usr/lib/systemd/hwdb/hwdb.bin",
		"/usr/lib/udev/hwdb.bin",
		"/lib/udev/hwdb.bin",
	};

	for (i = 0; !db && i < L_ARRAY_SIZE(paths); i++)
		db = l_hwdb_new(paths[i]);

	return db;
}

LIB_EXPORT struct l_hwdb *l_hwdb_ref(struct l_hwdb *hwdb)
{
	if (!hwdb)
		return NULL;

	__atomic_fetch_add(&hwdb->ref_count, 1, __ATOMIC_SEQ_CST);

	return hwdb;
}

LIB_EXPORT void l_hwdb_unref(struct l_hwdb *hwdb)
{
	if (!hwdb)
		return;

	if (__atomic_sub_fetch(&hwdb->ref_count, 1, __ATOMIC_SEQ_CST))
		return;

	munmap(hwdb->addr, hwdb->size);

	close(hwdb->fd);

	l_free(hwdb);
}

static void trie_fnmatch(struct l_hwdb *hwdb, uint64_t offset,
				const char *prefix, const char *string,
				struct l_hwdb_entry **entries)
{
	const void *addr = hwdb->addr;
	const struct trie_node *node = addr + offset;
	const void *addr_ptr = addr + offset + hwdb->node_size;
	const char *prefix_str = addr + L_LE64_TO_CPU(node->prefix_offset);
	uint8_t child_count = node->child_count;
	uint64_t entry_count = L_LE64_TO_CPU(node->entry_count);
	uint64_t i;
	size_t scratch_len;
	char *scratch_buf;

	scratch_len = strlen(prefix) + strlen(prefix_str);
	scratch_buf = alloca(scratch_len + 2);
	sprintf(scratch_buf, "%s%s", prefix, prefix_str);
	scratch_buf[scratch_len + 1] = '\0';

	/*
	 * Only incur the cost of this fnmatch() if there are children
	 * to visit.  In practice, nodes have either entries or children
	 * so fnmatch() will only be called once per node.
	 */
	if (child_count) {
		scratch_buf[scratch_len] = '*';

		if (fnmatch(scratch_buf, string, 0) == FNM_NOMATCH)
			child_count = 0;
	}

	for (i = 0; i < child_count; i++) {
		const struct trie_child *child = addr_ptr;

		scratch_buf[scratch_len] = child->c;

		trie_fnmatch(hwdb, L_LE64_TO_CPU(child->child_offset),
						scratch_buf, string, entries);

		addr_ptr += hwdb->child_size;
	}

	if (!entry_count)
		return;

	scratch_buf[scratch_len] = '\0';

	if (fnmatch(scratch_buf, string, 0))
		return;

	for (i = 0; i < entry_count; i++) {
		const struct trie_entry *entry = addr_ptr;
		const char *key_str = addr + L_LE64_TO_CPU(entry->key_offset);
		const char *val_str = addr + L_LE64_TO_CPU(entry->value_offset);
		struct l_hwdb_entry *result;

		if (key_str[0] == ' ') {
			result = l_new(struct l_hwdb_entry, 1);

			result->key = key_str + 1;
			result->value = val_str;
			result->next = (*entries);
			*entries = result;
		}

		addr_ptr += hwdb->entry_size;
	}
}

LIB_EXPORT struct l_hwdb_entry *l_hwdb_lookup(struct l_hwdb *hwdb,
						const char *format, ...)
{
	struct l_hwdb_entry *entries = NULL;
	va_list args;

	va_start(args, format);
	entries = l_hwdb_lookup_valist(hwdb, format, args);
	va_end(args);

	return entries;
}

LIB_EXPORT struct l_hwdb_entry *l_hwdb_lookup_valist(struct l_hwdb *hwdb,
					const char *format, va_list args)
{
	struct l_hwdb_entry *entries = NULL;
	char *modalias;
	int len;

	if (!hwdb || !format)
		return NULL;

	len = vasprintf(&modalias, format, args);
	if (len < 0)
		return NULL;

	trie_fnmatch(hwdb, hwdb->root_offset, "", modalias, &entries);

	free(modalias);

	return entries;
}

LIB_EXPORT void l_hwdb_lookup_free(struct l_hwdb_entry *entries)
{
	while (entries) {
		struct l_hwdb_entry *entry = entries;

		entries = entries->next;

		l_free(entry);
	}
}

static void foreach_node(struct l_hwdb *hwdb,
				uint64_t offset, const char *prefix,
				l_hwdb_foreach_func_t func, void *user_data)
{
	const void *addr = hwdb->addr;
	const struct trie_node *node = addr + offset;
	const void *addr_ptr = addr + offset + hwdb->node_size;
	const char *prefix_str = addr + L_LE64_TO_CPU(node->prefix_offset);
	uint8_t child_count = node->child_count;
	uint64_t entry_count = L_LE64_TO_CPU(node->entry_count);
	uint64_t i;
	size_t scratch_len;
	char *scratch_buf;
	struct l_hwdb_entry *entries = NULL;

	scratch_len = strlen(prefix) + strlen(prefix_str);
	scratch_buf = alloca(scratch_len + 2);
	sprintf(scratch_buf, "%s%s", prefix, prefix_str);
	scratch_buf[scratch_len + 1] = '\0';

	for (i = 0; i < child_count; i++) {
		const struct trie_child *child = addr_ptr;

		scratch_buf[scratch_len] = child->c;

		foreach_node(hwdb, L_LE64_TO_CPU(child->child_offset),
						scratch_buf, func, user_data);

		addr_ptr += hwdb->child_size;
	}

	if (!entry_count)
		return;

	scratch_buf[scratch_len] = '\0';

	for (i = 0; i < entry_count; i++) {
		const struct trie_entry *entry = addr_ptr;
		const char *key_str = addr + L_LE64_TO_CPU(entry->key_offset);
		const char *val_str = addr + L_LE64_TO_CPU(entry->value_offset);
		struct l_hwdb_entry *result;

		if (key_str[0] == ' ') {
			result = l_new(struct l_hwdb_entry, 1);

			result->key = key_str + 1;
			result->value = val_str;
			result->next = entries;
			entries = result;
		}

		addr_ptr += hwdb->entry_size;
	}

	func(scratch_buf, entries, user_data);

	l_hwdb_lookup_free(entries);
}

LIB_EXPORT bool l_hwdb_foreach(struct l_hwdb *hwdb, l_hwdb_foreach_func_t func,
							void *user_data)
{
	if (!hwdb || !func)
		return false;

	foreach_node(hwdb, hwdb->root_offset, "", func, user_data);

	return true;
}

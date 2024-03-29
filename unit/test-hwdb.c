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

#include <ell/ell.h>

struct hwdb_stats {
	int aliases;
	int entries;
};

static void print_modalias(struct l_hwdb *hwdb, const char *format, ...)
{
	struct l_hwdb_entry *entries, *entry;
	va_list args;

	va_start(args, format);
	vprintf(format, args);
	va_end(args);

	printf("\n");

	va_start(args, format);
	entries = l_hwdb_lookup_valist(hwdb, format, args);
	va_end(args);

	for (entry = entries; entry; entry = entry->next)
		printf(" %s=%s\n", entry->key, entry->value);

	l_hwdb_lookup_free(entries);

	printf("\n");
}

static void check_entry(const char *modalias, struct l_hwdb_entry *entries,
			void *user_data)
{
	struct l_hwdb_entry *entry;
	struct hwdb_stats *stats = user_data;

	assert(modalias);
	stats->aliases++;

	for (entry = entries; entry; entry = entry->next) {
		assert(entry->key);
		assert(entry->value);
		stats->entries++;
	}
}

int main(int argc, char *argv[])
{
	struct l_hwdb *hwdb;
	struct hwdb_stats stats = { 0 };

	hwdb = l_hwdb_new_default();
	if (!hwdb) {
		printf("hwdb.bin not loaded\n");
		return 0;
	}

	l_hwdb_foreach(hwdb, check_entry, &stats);
	printf("Found %d aliases with %d total entries\n\n",
	       stats.aliases, stats.entries);

	/* Bluetooth Interest Group Inc. */
	print_modalias(hwdb, "OUI:000F79");

	/* Bluetooth SIG, Inc. */
	print_modalias(hwdb, "bluetooth:v%04X", 0x003f);

	/* Nike+ FuelBand */
	print_modalias(hwdb, "bluetooth:v%04Xp%04X", 0x0078, 0x0001);

	/* Bluetooth Type-A standard interface */
	print_modalias(hwdb, "sdio:c02");

	l_hwdb_unref(hwdb);

	return 0;
}

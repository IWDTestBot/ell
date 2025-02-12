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

	va_start(args, format);
	entries = l_hwdb_lookup_valist(hwdb, format, args);
	va_end(args);

	for (entry = entries; entry; entry = entry->next)
		fprintf(stderr, " %s=%s\n", entry->key, entry->value);

	l_hwdb_lookup_free(entries);
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

static void test_hwdb(const void *data)
{
	struct l_hwdb *hwdb;
	struct hwdb_stats stats = { 0 };
	bool result;

	hwdb = l_hwdb_new_default();
	assert(hwdb);

	result = l_hwdb_foreach(hwdb, check_entry, &stats);
	assert(result);

	fprintf(stderr, "Found %d aliases with %d total entries\n",
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
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("hwdb", test_hwdb, NULL);

	return l_test_run();
}

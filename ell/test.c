/*
 * Embedded Linux library
 * Copyright (C) 2011-2014  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "log.h"
#include "test.h"
#include "private.h"
#include "useful.h"

/**
 * SECTION:test
 * @short_description: Unit test framework
 *
 * Unit test framework
 */

struct test {
	const char *name;
	l_test_func_t function;
	const void *test_data;
	struct test *next;
	unsigned int num;
};

static struct test *test_head;
static struct test *test_tail;
static unsigned int test_count;
static bool uses_own_main = false;

static bool cmd_list;
static bool tap_enable;
static bool debug_enable;

/**
 * l_test_init:
 * @argc: pointer to @argc parameter of main() function
 * @argv: pointer to @argv parameter of main() function
 *
 * Initialize testing framework.
 **/
LIB_EXPORT void l_test_init(int *argc, char ***argv)
{
	static const struct option options[] = {
		{ "list",	no_argument,	NULL, 'l' },
		{ "text",	no_argument,	NULL, 't' },
		{ "debug",	no_argument,	NULL, 'd' },
		{ }
	};

	test_head = NULL;
	test_tail = NULL;
	test_count = 0;

	l_log_set_stderr();

	cmd_list = false;
	tap_enable = true;
	debug_enable = false;

	for (;;) {
		int opt;

		opt = getopt_long(*argc, *argv, "ltd", options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'l':
			cmd_list = true;
			tap_enable = false;
			break;
		case 't':
			tap_enable = false;
			break;
		case 'd':
			debug_enable = true;
			break;
		}
	}
}

/**
 * l_test_run:
 *
 * Run all configured tests.
 *
 * Returns: 0 on success
 **/
LIB_EXPORT int l_test_run(void)
{
	struct test *test = test_head;

	if (tap_enable) {
		printf("TAP version 12\n");
		printf("1..%u\n", test_count);
	}

	if (debug_enable)
		l_debug_enable("*");

	while (test) {
		struct test *tmp = test;

		if (!tap_enable)
			printf("TEST: %s\n", test->name);

		if (!cmd_list) {
			test->function(test->test_data);
			if (tap_enable)
				printf("ok %u - %s\n", test->num, test->name);
		}

		test = test->next;
		test_head = test;

		free(tmp);
	}

	test_head = NULL;
	test_tail = NULL;
	test_count = 0;

	return 0;
}

/**
 * l_test_add:
 * @name: test name
 * @function: test function
 * @test_data: test data
 *
 * Add new test.
 **/
LIB_EXPORT void l_test_add(const char *name, l_test_func_t function,
						const void *test_data)
{
	struct test *test;

	if (unlikely(!name || !function))
		return;

	test = malloc(sizeof(struct test));
	if (!test)
		return;

	memset(test, 0, sizeof(struct test));
	test->name = name;
	test->function = function;
	test->test_data = test_data;
	test->next = NULL;

	if (test_tail)
		test_tail->next = test;

	test_tail = test;

	if (!test_head)
		test_head = test;

	test->num = ++test_count;
}

/**
 * l_test_set_uses_own_main:
 *
 * Set state for tests using their own main loop.
 **/
LIB_EXPORT void l_test_set_uses_own_main(void)
{
	uses_own_main = true;
}

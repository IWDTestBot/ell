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

#include <ell/ell.h>

static void test_add(const void *data)
{
	assert(1);
}

static void test_add_func(const void *data)
{
	assert(1);
}

static void test_add_data_func(const void *data)
{
	assert(1);
}

static void test_add_func_fail(const void *data)
{
	assert(0);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("add", test_add, NULL);
	l_test_add_func("add-func", test_add_func, 0);
	l_test_add_data_func("add-data-func", NULL, test_add_data_func, 0);
	l_test_add_func("add-func-fail", test_add_func_fail,
						L_TEST_FLAG_FAILURE_EXPECTED);

	return l_test_run();
}

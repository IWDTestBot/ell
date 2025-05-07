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

static void ready_callback(void *user_data)
{
	l_info("D-Bus ready");
	l_main_quit();
}

static void disconnect_callback(void *user_data)
{
	l_info("D-Bus disconnect");
	l_main_quit();
}

static void test_dbus_system_bus(const void *data)
{
	struct l_dbus *dbus;

	dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);
	assert(dbus);

	l_dbus_set_ready_handler(dbus, ready_callback, NULL, NULL);
	l_dbus_set_disconnect_handler(dbus, disconnect_callback, NULL, NULL);
}

static void test_dbus_session_bus(const void *data)
{
	struct l_dbus *dbus;

	dbus = l_dbus_new_default(L_DBUS_SESSION_BUS);
	assert(dbus);

	l_dbus_set_ready_handler(dbus, ready_callback, NULL, NULL);
	l_dbus_set_disconnect_handler(dbus, disconnect_callback, NULL, NULL);
}

static void test_ok(const void *data)
{
	assert(1);
}

static void test_fail(const void *data)
{
	assert(0);
}

static bool precheck_success(const void *data)
{
	return true;
}

static bool precheck_failure(const void *data)
{
	return false;
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("add", test_add, NULL);
	l_test_add_func("add-func", test_add_func, 0);
	l_test_add_data_func("add-data-func", NULL, test_add_data_func, 0);
	l_test_add_func("add-func-fail", test_add_func_fail,
						L_TEST_FLAG_FAILURE_EXPECTED);

	l_test_add_func("dbus-system-bus", test_dbus_system_bus,
					L_TEST_FLAG_ALLOW_FAILURE |
					L_TEST_FLAG_REQUIRE_DBUS_SYSTEM_BUS);
	l_test_add_func("dbus-session-bus", test_dbus_session_bus,
					L_TEST_FLAG_ALLOW_FAILURE |
					L_TEST_FLAG_REQUIRE_DBUS_SESSION_BUS);

	l_test_add_func_precheck("add-precheck-success",
					test_ok, precheck_success, 0);
	l_test_add_func_precheck("add-precheck-failure",
					test_ok, precheck_failure,
					L_TEST_FLAG_INVERT_PRECHECK_RESULT);
	l_test_add_func_precheck("add-precheck-success-fail",
					test_fail, precheck_success,
					L_TEST_FLAG_FAILURE_EXPECTED);

	return l_test_run();
}

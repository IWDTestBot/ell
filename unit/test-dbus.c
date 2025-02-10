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

#define TEST_BUS_ADDRESS_UNIX "unix:path=/tmp/ell-test-bus"
#define TEST_BUS_ADDRESS_TCP "tcp:host=127.0.0.1,port=14046"

static bool match_cb_called;
static bool req_name_cb_called;

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void signal_message(struct l_dbus_message *message, void *user_data)
{
	const char *path, *interface, *member, *destination, *sender;

	path = l_dbus_message_get_path(message);
	destination = l_dbus_message_get_destination(message);

	l_info("path=%s destination=%s", path, destination);

	interface = l_dbus_message_get_interface(message);
	member = l_dbus_message_get_member(message);

	l_info("interface=%s member=%s", interface, member);

	sender = l_dbus_message_get_sender(message);

	l_info("sender=%s", sender);

	if (!strcmp(member, "NameOwnerChanged")) {
		const char *name, *old_owner, *new_owner;

		if (!l_dbus_message_get_arguments(message, "sss",
					&name, &old_owner, &new_owner))
			return;

		l_info("name=%s old=%s new=%s", name, old_owner, new_owner);
	}
}

static void request_name_setup(struct l_dbus_message *message, void *user_data)
{
	const char *name = "org.test";

	l_dbus_message_set_arguments(message, "su", name, 0);
}

static void request_name_callback(struct l_dbus_message *message,
							void *user_data)
{
	const char *error, *text;
	uint32_t result;

	req_name_cb_called = true;

	if (l_dbus_message_get_error(message, &error, &text)) {
		l_error("error=%s", error);
		l_error("message=%s", text);
		assert(false);
	}

	assert(l_dbus_message_get_arguments(message, "u", &result));

	l_info("request name result=%d", result);

	l_main_quit();
}

static const char *match_rule = "type=signal,sender=org.freedesktop.DBus";

static void add_match_setup(struct l_dbus_message *message, void *user_data)
{
	l_dbus_message_set_arguments(message, "s", match_rule);
}

static void add_match_callback(struct l_dbus_message *message, void *user_data)
{
	const char *error, *text;

	match_cb_called = true;

	if (l_dbus_message_get_error(message, &error, &text)) {
		l_error("error=%s", error);
		l_error("message=%s", text);
		assert(false);
		return;
	}

	assert(l_dbus_message_get_arguments(message, ""));

	l_info("add match");
}

static void ready_callback(void *user_data)
{
	struct l_dbus *dbus = user_data;
	int rc;

	l_info("ready");

	rc = l_dbus_method_call(dbus, "org.freedesktop.DBus",
				"/org/freedesktop/DBus",
				"org.freedesktop.DBus", "AddMatch",
				add_match_setup,
				add_match_callback, NULL, NULL);
	assert(rc > 0);

	rc = l_dbus_method_call(dbus, "org.freedesktop.DBus",
				"/org/freedesktop/DBus",
				"org.freedesktop.DBus", "RequestName",
				request_name_setup,
				request_name_callback, NULL, NULL);
	assert(rc > 0);
}

static void disconnect_callback(void *user_data)
{
	l_main_quit();
}

static void test_unix_dbus(const void *data)
{
	struct l_dbus *dbus;

	match_cb_called = false;
	req_name_cb_called = false;

	dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);
	assert(dbus);

	l_dbus_set_debug(dbus, do_debug, "[DBUS] ", NULL);

	l_dbus_set_ready_handler(dbus, ready_callback, dbus, NULL);
	l_dbus_set_disconnect_handler(dbus, disconnect_callback, NULL, NULL);

	l_dbus_register(dbus, signal_message, NULL, NULL);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add_func("Using a unix socket", test_unix_dbus,
					L_TEST_FLAG_ALLOW_FAILURE |
					L_TEST_FLAG_REQUIRE_DBUS_SYSTEM_BUS);

	return l_test_run();
}

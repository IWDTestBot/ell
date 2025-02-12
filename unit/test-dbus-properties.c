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
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>

#include <ell/ell.h>
#include "ell/dbus-private.h"

#define ROOT_PATH "/ell/test"

struct l_dbus *dbus;

static void setup_bus(void);

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void request_name_callback(struct l_dbus *dbus, bool success,
					bool queued, void *user_data)
{
	l_info("request name result=%s",
		success ? (queued ? "queued" : "success") : "failed");
}

static void ready_callback(void *user_data)
{
	l_info("ready");
}

static void disconnect_callback(void *user_data)
{
	l_info("Disconnected from DBus");
	l_main_quit();
}

static bool test_string_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	return l_dbus_message_builder_append_basic(builder, 's', "foo");
}

static bool setter_called;
static bool int_optional;

static struct l_dbus_message *test_string_setter(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	const char *strvalue;

	if (!l_dbus_message_iter_get_variant(new_value, "s", &strvalue))
		goto done;

	if (strcmp(strvalue, "bar"))
		goto done;

	setter_called = true;

done:
	complete(dbus, message, NULL);

	return NULL;
}

static bool test_int_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	uint32_t u;

	if (int_optional)
		return false;

	u = 5;

	return l_dbus_message_builder_append_basic(builder, 'u', &u);
}

static struct l_dbus_message *test_int_setter(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	uint32_t u;

	if (!l_dbus_message_iter_get_variant(new_value, "u", &u))
		goto done;

	if (u != 42)
		goto done;

	setter_called = true;

done:
	return l_dbus_message_new_method_return(message);
}

static struct l_dbus_message *test_error_setter(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	setter_called = true;

	return l_dbus_message_new_error(message, "org.test.Error", "Error");
}

static bool test_path_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	return l_dbus_message_builder_append_basic(builder, 'o', "/foo/bar");
}

static void setup_test_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_property(interface, "String",
					L_DBUS_PROPERTY_FLAG_AUTO_EMIT, "s",
					test_string_getter, test_string_setter);
	l_dbus_interface_property(interface, "Integer",
					L_DBUS_PROPERTY_FLAG_AUTO_EMIT, "u",
					test_int_getter, test_int_setter);
	l_dbus_interface_property(interface, "Readonly", 0, "s",
					test_string_getter, NULL);
	l_dbus_interface_property(interface, "SetError", 0, "s",
					test_string_getter, test_error_setter);
	l_dbus_interface_property(interface, "Path", 0, "o",
					test_path_getter, NULL);
}

static void validate_properties(struct l_dbus_message_iter *dict)
{
	struct l_dbus_message_iter variant;
	const char *name, *strval;
	uint32_t intval;

	assert(l_dbus_message_iter_next_entry(dict, &name, &variant));
	assert(!strcmp(name, "String"));
	assert(l_dbus_message_iter_get_variant(&variant, "s", &strval));
	assert(!strcmp(strval, "foo"));

	if (!int_optional) {
		assert(l_dbus_message_iter_next_entry(dict, &name,
								&variant));
		assert(!strcmp(name, "Integer"));
		assert(l_dbus_message_iter_get_variant(&variant, "u",
								&intval));
		assert(intval == 5);
	}

	assert(l_dbus_message_iter_next_entry(dict, &name, &variant));
	assert(!strcmp(name, "Readonly"));
	assert(l_dbus_message_iter_get_variant(&variant, "s", &strval));
	assert(!strcmp(strval, "foo"));

	assert(l_dbus_message_iter_next_entry(dict, &name, &variant));
	assert(!strcmp(name, "SetError"));
	assert(l_dbus_message_iter_get_variant(&variant, "s", &strval));
	assert(!strcmp(strval, "foo"));

	assert(l_dbus_message_iter_next_entry(dict, &name, &variant));
	assert(!strcmp(name, "Path"));
	assert(l_dbus_message_iter_get_variant(&variant, "o", &strval));
	assert(!strcmp(strval, "/foo/bar"));

	assert(!l_dbus_message_iter_next_entry(dict, &name, &variant));
}

static void get_properties_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message_iter dict;

	assert(!l_dbus_message_get_error(message, NULL, NULL));
	assert(l_dbus_message_get_arguments(message, "a{sv}", &dict));

	validate_properties(&dict);

	l_main_quit();
}

static void test_old_get(const void *data)
{
	struct l_dbus_message *call;

	setup_bus();

	call = l_dbus_message_new_method_call(dbus, "org.test",
						ROOT_PATH "/test",
						"org.test", "GetProperties");

	assert(call);
	assert(l_dbus_message_set_arguments(call, ""));

	assert(l_dbus_send_with_reply(dbus, call, get_properties_callback,
						NULL, NULL));
}

static void test_old_optional_get(const void *data)
{
	struct l_dbus_message *call;

	setup_bus();

	call = l_dbus_message_new_method_call(dbus, "org.test",
						ROOT_PATH "/test",
						"org.test", "GetProperties");

	int_optional = true;

	assert(call);
	assert(l_dbus_message_set_arguments(call, ""));

	assert(l_dbus_send_with_reply(dbus, call, get_properties_callback,
						NULL, NULL));
}
static void set_invalid_callback(struct l_dbus_message *message,
					void *user_data)
{
	assert(l_dbus_message_get_error(message, NULL, NULL));
	assert(!setter_called);

	l_main_quit();
}

static void old_set_error_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *call;

	assert(l_dbus_message_get_error(message, NULL, NULL));
	assert(setter_called);
	setter_called = false;

	call = l_dbus_message_new_method_call(dbus, "org.test",
						ROOT_PATH "/test",
						"org.test", "SetProperty");
	assert(call);
	assert(l_dbus_message_set_arguments(call, "sv", "Invalid",
							"s", "bar"));

	assert(l_dbus_send_with_reply(dbus, call, set_invalid_callback,
						NULL, NULL));
}

static void old_set_ro_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *call;

	assert(l_dbus_message_get_error(message, NULL, NULL));
	assert(!setter_called);

	call = l_dbus_message_new_method_call(dbus, "org.test",
						ROOT_PATH "/test",
						"org.test", "SetProperty");
	assert(call);
	assert(l_dbus_message_set_arguments(call, "sv", "SetError",
							"s", "bar"));

	assert(l_dbus_send_with_reply(dbus, call, old_set_error_callback,
						NULL, NULL));
}

static void old_set_int_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *call;

	assert(!l_dbus_message_get_error(message, NULL, NULL));
	assert(l_dbus_message_get_arguments(message, ""));
	assert(setter_called);
	setter_called = false;

	call = l_dbus_message_new_method_call(dbus, "org.test",
						ROOT_PATH "/test",
						"org.test", "SetProperty");
	assert(call);
	assert(l_dbus_message_set_arguments(call, "sv", "Readonly",
							"s", "bar"));

	assert(l_dbus_send_with_reply(dbus, call, old_set_ro_callback,
						NULL, NULL));
}

static void old_set_string_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *call;

	assert(!l_dbus_message_get_error(message, NULL, NULL));
	assert(l_dbus_message_get_arguments(message, ""));
	assert(setter_called);
	setter_called = false;

	call = l_dbus_message_new_method_call(dbus, "org.test",
						ROOT_PATH "/test",
						"org.test", "SetProperty");
	assert(call);
	assert(l_dbus_message_set_arguments(call, "sv", "Integer",
							"u", 42));

	assert(l_dbus_send_with_reply(dbus, call, old_set_int_callback,
						NULL, NULL));
}

static void test_old_set(const void *data)
{
	struct l_dbus_message *call;

	setup_bus();

	call = l_dbus_message_new_method_call(dbus, "org.test",
						ROOT_PATH "/test",
						"org.test", "SetProperty");

	assert(call);
	assert(l_dbus_message_set_arguments(call, "sv", "String",
							"s", "bar"));

	assert(!setter_called);
	assert(l_dbus_send_with_reply(dbus, call, old_set_string_callback,
						NULL, NULL));
}

static void new_get_invalid_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *call;

	assert(l_dbus_message_get_error(message, NULL, NULL));

	call = l_dbus_message_new_method_call(dbus, "org.test",
					ROOT_PATH "/test",
					"org.freedesktop.DBus.Properties",
					"GetAll");
	assert(call);
	assert(l_dbus_message_set_arguments(call, "s", "org.test"));

	assert(l_dbus_send_with_reply(dbus, call, get_properties_callback,
						NULL, NULL));
}

static void new_get_bad_if_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *call;

	assert(l_dbus_message_get_error(message, NULL, NULL));

	call = l_dbus_message_new_method_call(dbus, "org.test",
					ROOT_PATH "/test",
					"org.freedesktop.DBus.Properties",
					"Get");
	assert(call);
	assert(l_dbus_message_set_arguments(call, "ss",
							"org.test", "Invalid"));

	assert(l_dbus_send_with_reply(dbus, call, new_get_invalid_callback,
						NULL, NULL));
}

static void new_get_callback(struct l_dbus_message *message, void *user_data)
{
	struct l_dbus_message_iter variant;
	const char *strval;
	struct l_dbus_message *call;

	assert(!l_dbus_message_get_error(message, NULL, NULL));
	assert(l_dbus_message_get_arguments(message, "v", &variant));
	assert(l_dbus_message_iter_get_variant(&variant, "s", &strval));
	assert(!strcmp(strval, "foo"));

	call = l_dbus_message_new_method_call(dbus, "org.test",
					ROOT_PATH "/test",
					"org.freedesktop.DBus.Properties",
					"Get");
	assert(call);
	assert(l_dbus_message_set_arguments(call, "ss", "org.invalid",
							"String"));

	assert(l_dbus_send_with_reply(dbus, call, new_get_bad_if_callback,
						NULL, NULL));
}

static void test_new_get(const void *data)
{
	struct l_dbus_message *call;

	setup_bus();

	call = l_dbus_message_new_method_call(dbus, "org.test",
					ROOT_PATH "/test",
					"org.freedesktop.DBus.Properties",
					"Get");

	assert(call);
	assert(l_dbus_message_set_arguments(call, "ss",
							"org.test", "String"));

	assert(l_dbus_send_with_reply(dbus, call, new_get_callback,
						NULL, NULL));
}

static void new_set_bad_if_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *call;

	assert(l_dbus_message_get_error(message, NULL, NULL));
	assert(!setter_called);

	call = l_dbus_message_new_method_call(dbus, "org.test",
					ROOT_PATH "/test",
					"org.freedesktop.DBus.Properties",
					"Set");
	assert(call);
	assert(l_dbus_message_set_arguments(call, "ssv", "org.test",
							"Invalid", "s", "bar"));

	assert(l_dbus_send_with_reply(dbus, call, set_invalid_callback,
						NULL, NULL));
}

static void new_set_error_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *call;

	assert(l_dbus_message_get_error(message, NULL, NULL));
	assert(setter_called);
	setter_called = false;

	call = l_dbus_message_new_method_call(dbus, "org.test",
					ROOT_PATH "/test",
					"org.freedesktop.DBus.Properties",
					"Set");
	assert(call);
	assert(l_dbus_message_set_arguments(call, "ssv", "org.invalid",
							"String", "s", "bar"));

	assert(l_dbus_send_with_reply(dbus, call, new_set_bad_if_callback,
						NULL, NULL));
}

static void new_set_ro_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *call;

	assert(l_dbus_message_get_error(message, NULL, NULL));
	assert(!setter_called);

	call = l_dbus_message_new_method_call(dbus, "org.test",
					ROOT_PATH "/test",
					"org.freedesktop.DBus.Properties",
					"Set");
	assert(call);
	assert(l_dbus_message_set_arguments(call, "ssv", "org.test",
							"SetError",
							"s", "bar"));

	assert(l_dbus_send_with_reply(dbus, call, new_set_error_callback,
						NULL, NULL));
}

static void new_set_int_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *call;

	assert(!l_dbus_message_get_error(message, NULL, NULL));
	assert(l_dbus_message_get_arguments(message, ""));
	assert(setter_called);
	setter_called = false;

	call = l_dbus_message_new_method_call(dbus, "org.test",
					ROOT_PATH "/test",
					"org.freedesktop.DBus.Properties",
					"Set");
	assert(call);
	assert(l_dbus_message_set_arguments(call, "ssv", "org.test",
							"Readonly",
							"s", "bar"));

	assert(l_dbus_send_with_reply(dbus, call, new_set_ro_callback,
						NULL, NULL));
}

static void new_set_string_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *call;

	assert(!l_dbus_message_get_error(message, NULL, NULL));
	assert(l_dbus_message_get_arguments(message, ""));
	assert(setter_called);
	setter_called = false;

	call = l_dbus_message_new_method_call(dbus, "org.test",
					ROOT_PATH "/test",
					"org.freedesktop.DBus.Properties",
					"Set");
	assert(call);
	assert(l_dbus_message_set_arguments(call, "ssv", "org.test",
							"Integer", "u", 42));

	assert(l_dbus_send_with_reply(dbus, call, new_set_int_callback,
						NULL, NULL));
}

static void test_new_set(const void *data)
{
	struct l_dbus_message *call;

	setup_bus();

	call = l_dbus_message_new_method_call(dbus, "org.test",
					ROOT_PATH "/test",
					"org.freedesktop.DBus.Properties",
					"Set");

	assert(call);
	assert(l_dbus_message_set_arguments(call, "ssv", "org.test",
							"String", "s", "bar"));

	assert(!setter_called);
	assert(l_dbus_send_with_reply(dbus, call, new_set_string_callback,
						NULL, NULL));
}

static struct l_timeout *signal_timeout;

static void signal_timeout_callback(struct l_timeout *timeout, void *user_data)
{
	signal_timeout = NULL;
	assert(false);
}

static bool old_signal_received, new_signal_received;
static bool signal_success;

static void test_check_signal_success(void)
{
	struct l_dbus_message *call;

	if (!old_signal_received || !new_signal_received)
		return;

	l_timeout_remove(signal_timeout);
	signal_timeout = NULL;

	if (!signal_success) {
		signal_success = true;

		/* Now repeat the test for the signal triggered by Set */

		old_signal_received = false;
		new_signal_received = false;

		signal_timeout = l_timeout_create(1, signal_timeout_callback,
							NULL, NULL);
		assert(signal_timeout);

		call = l_dbus_message_new_method_call(dbus, "org.test",
					ROOT_PATH "/test",
					"org.freedesktop.DBus.Properties",
					"Set");
		assert(call);
		assert(l_dbus_message_set_arguments(call, "ssv",
							"org.test", "String",
							"s", "bar"));

		assert(!setter_called);
		assert(l_dbus_send(dbus, call));
	} else {
		assert(setter_called);
		setter_called = false;

		l_main_quit();
	}
}

static void test_old_signal_callback(struct l_dbus_message *message,
					void *user_data)
{
	const char *property, *value;
	struct l_dbus_message_iter variant;

	if (!signal_timeout)
		return;

	assert(l_dbus_message_get_arguments(message, "sv",
							&property, &variant));
	assert(!strcmp(property, "String"));
	assert(l_dbus_message_iter_get_variant(&variant, "s", &value));
	assert(!strcmp(value, "foo"));

	assert(!old_signal_received);
	old_signal_received = true;

	test_check_signal_success();
}

static void test_new_signal_callback(struct l_dbus_message *message,
					void *user_data)
{
	const char *interface, *property, *value;
	struct l_dbus_message_iter variant, changed, invalidated;

	if (!signal_timeout)
		return;

	assert(l_dbus_message_get_arguments(message, "sa{sv}as",
							&interface, &changed,
							&invalidated));

	assert(l_dbus_message_iter_next_entry(&changed, &property,
							&variant));
	assert(!strcmp(property, "String"));
	assert(l_dbus_message_iter_get_variant(&variant, "s", &value));
	assert(!strcmp(value, "foo"));

	assert(!l_dbus_message_iter_next_entry(&changed, &property,
							&variant));
	assert(!l_dbus_message_iter_next_entry(&invalidated,
							&property));

	assert(!new_signal_received);
	new_signal_received = true;

	test_check_signal_success();
}

static void test_property_signals(const void *data)
{
	setup_bus();

	old_signal_received = false;
	new_signal_received = false;

	signal_timeout = l_timeout_create(1, signal_timeout_callback,
						NULL, NULL);
	assert(signal_timeout);

	assert(l_dbus_property_changed(dbus, ROOT_PATH "/test",
						"org.test", "String"));
}

static void object_manager_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message_iter objects, interfaces, properties, variant;
	const char *path, *interface, *name;
	bool object_manager_found = false;
	bool test_found = false;
	bool properties_found = false;

	assert(!l_dbus_message_get_error(message, NULL, NULL));
	assert(l_dbus_message_get_arguments(message, "a{oa{sa{sv}}}",
							&objects));

	while (l_dbus_message_iter_next_entry(&objects, &path, &interfaces)) {
		while (l_dbus_message_iter_next_entry(&interfaces, &interface,
							&properties)) {
			if (!strcmp(path, ROOT_PATH) && !strcmp(interface,
					"org.freedesktop.DBus.ObjectManager")) {
				assert(!object_manager_found);
				object_manager_found = true;
				assert(!l_dbus_message_iter_next_entry(
							&properties, &name,
							&variant));
			}

			if (!strcmp(path, ROOT_PATH "/test") &&
					!strcmp(interface,
					"org.freedesktop.DBus.Properties")) {
				assert(!properties_found);
				properties_found = true;
				assert(!l_dbus_message_iter_next_entry(
							&properties, &name,
							&variant));
			}

			if (!strcmp(path, ROOT_PATH "/test") &&
					!strcmp(interface, "org.test")) {
				assert(!test_found);
				test_found = true;
				validate_properties(&properties);
			}
		}
	}

	assert(object_manager_found && test_found && properties_found);

	l_main_quit();
}

static void test_object_manager_get(const void *data)
{
	struct l_dbus_message *call;

	setup_bus();

	call = l_dbus_message_new_method_call(dbus, "org.test",
					ROOT_PATH,
					"org.freedesktop.DBus.ObjectManager",
					"GetManagedObjects");

	assert(call);
	assert(l_dbus_message_set_arguments(call, ""));

	assert(l_dbus_send_with_reply(dbus, call, object_manager_callback,
						NULL, NULL));
}

static struct l_timeout *om_signal_timeout;

static void om_signal_timeout_callback(struct l_timeout *timeout,
					void *user_data)
{
	om_signal_timeout = NULL;
	assert(false);
}

static bool expect_interfaces_added;

static void om_signal_callback(struct l_dbus_message *message, void *user_data)
{
	const char *path, *interface, *member;
	struct l_dbus_message_iter interfaces, properties;

	if (!om_signal_timeout)
		return;

	member = l_dbus_message_get_member(message);

	if (!strcmp(member, "InterfacesAdded"))
		assert(expect_interfaces_added);
	else if (!strcmp(member, "InterfacesRemoved"))
		assert(!expect_interfaces_added);
	else
		return;

	if (!strcmp(member, "InterfacesAdded")) {
		assert(l_dbus_message_get_arguments(message, "oa{sa{sv}}",
								&path,
								&interfaces));
		assert(!strcmp(path, ROOT_PATH "/test2"));

		assert(l_dbus_message_iter_next_entry(&interfaces,
								&interface,
								&properties));
		assert(!strcmp(interface, "org.test"));
		validate_properties(&properties);

		assert(!l_dbus_message_iter_next_entry(&interfaces,
								&interface,
								&properties));

		/* Now repeat the test for the InterfacesRemoved signal */

		expect_interfaces_added = false;
		assert(l_dbus_unregister_object(dbus, ROOT_PATH "/test2"));
	} else {
		assert(l_dbus_message_get_arguments(message, "oas",
								&path,
								&interfaces));
		assert(!strcmp(path, ROOT_PATH "/test2"));

		assert(l_dbus_message_iter_next_entry(&interfaces,
								&interface));
		assert(!strcmp(interface, "org.test"));

		assert(!l_dbus_message_iter_next_entry(&interfaces,
								&interface));

		l_timeout_remove(om_signal_timeout);
		om_signal_timeout = NULL;

		l_main_quit();
	}
}

static void test_object_manager_signals(const void *data)
{
	setup_bus();

	om_signal_timeout = l_timeout_create(1, om_signal_timeout_callback,
						NULL, NULL);
	assert(om_signal_timeout);

	expect_interfaces_added = true;
	assert(l_dbus_object_add_interface(dbus, ROOT_PATH "/test2",
						"org.test", NULL));
}

static void setup_bus(void)
{
	dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);
	assert(dbus);

	l_dbus_set_debug(dbus, do_debug, "[DBUS] ", NULL);

	l_dbus_set_ready_handler(dbus, ready_callback, NULL, NULL);
	l_dbus_set_disconnect_handler(dbus, disconnect_callback, NULL, NULL);

	l_dbus_name_acquire(dbus, "org.test", false, false, false,
						request_name_callback, NULL);

	if (!l_dbus_register_interface(dbus, "org.test", setup_test_interface,
					NULL, true)) {
		l_info("Unable to register interface");
		return;
	}

	if (!l_dbus_object_add_interface(dbus, ROOT_PATH "/test",
						"org.test", NULL)) {
		l_info("Unable to instantiate interface");
		return;
	}

	if (!l_dbus_object_add_interface(dbus, ROOT_PATH "/test",
				"org.freedesktop.DBus.Properties", NULL)) {
		l_info("Unable to instantiate the properties interface");
		return;
	}

	l_dbus_add_signal_watch(dbus, "org.test", ROOT_PATH "/test", "org.test",
				"PropertyChanged", L_DBUS_MATCH_NONE,
				test_old_signal_callback, NULL);
	l_dbus_add_signal_watch(dbus, "org.test", ROOT_PATH "/test",
				"org.freedesktop.DBus.Properties",
				"PropertiesChanged", L_DBUS_MATCH_ARGUMENT(0),
				"org.test", L_DBUS_MATCH_NONE,
				test_new_signal_callback, NULL);

	if (!l_dbus_object_manager_enable(dbus, ROOT_PATH)) {
		l_info("Unable to enable Object Manager");
		return;
	}

	l_dbus_add_signal_watch(dbus, "org.test", ROOT_PATH,
				"org.freedesktop.DBus.ObjectManager",
				NULL, L_DBUS_MATCH_NONE,
				om_signal_callback, NULL);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add_func("Legacy properties get", test_old_get,
					L_TEST_FLAG_ALLOW_FAILURE |
					L_TEST_FLAG_REQUIRE_DBUS_SYSTEM_BUS);
	l_test_add_func("Legacy properties set", test_old_set,
					L_TEST_FLAG_ALLOW_FAILURE |
					L_TEST_FLAG_REQUIRE_DBUS_SYSTEM_BUS);
	l_test_add_func("Legacy optional property", test_old_optional_get,
					L_TEST_FLAG_ALLOW_FAILURE |
					L_TEST_FLAG_REQUIRE_DBUS_SYSTEM_BUS);
	l_test_add_func("org.freedesktop.DBus.Properties get", test_new_get,
					L_TEST_FLAG_ALLOW_FAILURE |
					L_TEST_FLAG_REQUIRE_DBUS_SYSTEM_BUS);
	l_test_add_func("org.freedesktop.DBus.Properties set", test_new_set,
					L_TEST_FLAG_ALLOW_FAILURE |
					L_TEST_FLAG_REQUIRE_DBUS_SYSTEM_BUS);
	l_test_add_func("Property changed signals", test_property_signals,
					L_TEST_FLAG_ALLOW_FAILURE |
					L_TEST_FLAG_REQUIRE_DBUS_SYSTEM_BUS);
	l_test_add_func("org.freedesktop.DBus.ObjectManager get",
					test_object_manager_get,
					L_TEST_FLAG_ALLOW_FAILURE |
					L_TEST_FLAG_REQUIRE_DBUS_SYSTEM_BUS);
	l_test_add_func("org.freedesktop.DBus.ObjectManager signals",
					test_object_manager_signals,
					L_TEST_FLAG_ALLOW_FAILURE |
					L_TEST_FLAG_REQUIRE_DBUS_SYSTEM_BUS);

	return l_test_run();
}

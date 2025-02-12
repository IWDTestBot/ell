/*
 * Embedded Linux library
 * Copyright (C) 2016  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <ell/ell.h>
#include "ell/dbus-private.h"

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static int count_fds(void)
{
	int fd;
	int count = 0;
	int flags;

	for (fd = 0; fd < FD_SETSIZE; fd++) {
		flags = fcntl(fd, F_GETFL);
		if (flags < 0) /* ignore any files we can't operate on */
			continue;

		/*
		 * Only count files that are read-only or write-only.  This is
		 * to work around the issue that fakeroot opens a TCP socket
		 * in RDWR mode in a separate thread
		 *
		 * Note: This means that files used for file-descriptor passing
		 * tests should be opened RDONLY or WRONLY
		 */
		if (flags & O_RDWR)
			continue;

		count++;
	}

	return count;
}

static int open_fds;

static void get_random_idle_callback(void *user_data)
{
	int new_open_fds;

	new_open_fds = count_fds();
	l_info("new open file descriptors %d", new_open_fds);

	assert(new_open_fds == open_fds);

	l_main_quit();
}

static void get_random_return_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct stat sa, sb;
	int fd0, fd1;

	assert(!l_dbus_message_get_error(message, NULL, NULL));

	assert(l_dbus_message_get_arguments(message, "h", &fd1));

	fd0 = open("/dev/random", O_RDONLY);
	assert(fd0 != -1);

	/* compare files */
	assert(fstat(fd0, &sa) == 0);
	assert(fstat(fd1, &sb) == 0);

	assert(sa.st_dev == sb.st_dev);
	assert(sa.st_ino == sb.st_ino);
	assert(sa.st_rdev == sb.st_rdev);

	close(fd0);
	close(fd1);

	assert(l_idle_oneshot(get_random_idle_callback, NULL, NULL));
}

static void request_name_callback(struct l_dbus *dbus, bool success,
					bool queued, void *user_data)
{
	uint32_t id;

	l_info("request name result=%s",
		success ? (queued ? "queued" : "success") : "failed");

	open_fds = count_fds();
	l_info("open file descriptors %d", open_fds);

	id = l_dbus_method_call(dbus, "org.test", "/test", "org.test",
				"GetRandom", NULL,
				get_random_return_callback, NULL, NULL);
	assert(id > 0);
}

static void ready_callback(void *user_data)
{
	struct l_dbus *dbus = user_data;

	l_info("ready");

	l_dbus_name_acquire(dbus, "org.test", false, false, false,
						request_name_callback, NULL);
}

static void disconnect_callback(void *user_data)
{
	l_info("Disconnected from DBus");
	l_main_quit();
}

static struct l_dbus_message *get_random_callback(struct l_dbus *dbus,
					struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *reply;
	int fd;

	reply = l_dbus_message_new_method_return(message);

	fd = open("/dev/random", O_RDONLY);
	l_dbus_message_set_arguments(reply, "h", fd);
	close(fd);

	return reply;
}

static void setup_test_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "GetRandom", 0, get_random_callback,
				"h", "", "randomfd");
}

static void test_fd_passing_1(const void *data)
{
	struct l_dbus *dbus;
	bool result;

	dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);
	assert(dbus);

	l_dbus_set_debug(dbus, do_debug, "[DBUS] ", NULL);

	l_dbus_set_ready_handler(dbus, ready_callback, dbus, NULL);
	l_dbus_set_disconnect_handler(dbus, disconnect_callback, NULL, NULL);

	result = l_dbus_register_interface(dbus, "org.test",
					setup_test_interface, NULL, true);
	assert(result);

	result = l_dbus_object_add_interface(dbus, "/test", "org.test", NULL);
	assert(result);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add_func("FD passing 1", test_fd_passing_1,
					L_TEST_FLAG_ALLOW_FAILURE |
					L_TEST_FLAG_REQUIRE_DBUS_SYSTEM_BUS);

	return l_test_run();
}

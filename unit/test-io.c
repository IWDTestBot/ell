/*
 * Embedded Linux library
 * Copyright (C) 2011-2014  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <sys/socket.h>

#include <ell/ell.h>

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static bool write_handler(struct l_io *io, void *user_data)
{
	int fd = l_io_get_fd(io);
	char *str = "Hello";
	ssize_t written;

	written = write(fd, str, strlen(str));
	assert(written > 0);

	l_info("%zd bytes written", written);

	return false;
}

static bool read_handler(struct l_io *io, void *user_data)
{
	int fd = l_io_get_fd(io);
	char str[32];
	ssize_t result;

	result = read(fd, str, sizeof(str));
	assert(result > 0);

	l_info("%zd bytes read", result);

	l_main_quit();

	return false;
}

static void disconnect_handler(struct l_io *io, void *user_data)
{
	l_info("disconnect");
}

static void test_io(const void *data)
{
	struct l_io *io1, *io2;
	int fd[2];
	int exit_status;

	assert(l_main_init());

	l_log_set_stderr();

	if (socketpair(PF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd) < 0) {
		l_error("Failed to create socket pair");
		abort();
		return;
	}

	io1 = l_io_new(fd[0]);
	l_io_set_close_on_destroy(io1, true);
	l_io_set_debug(io1, do_debug, "[IO-1] ", NULL);
	l_io_set_read_handler(io1, read_handler, NULL, NULL);
	l_io_set_disconnect_handler(io1, disconnect_handler, NULL, NULL);

	io2 = l_io_new(fd[1]);
	l_io_set_close_on_destroy(io2, true);
	l_io_set_debug(io2, do_debug, "[IO-2] ", NULL);
	l_io_set_write_handler(io2, write_handler, NULL, NULL);
	l_io_set_disconnect_handler(io2, disconnect_handler, NULL, NULL);

	assert(io1);
	assert(io2);

	exit_status = l_main_run();
	assert(exit_status == EXIT_SUCCESS);

	l_io_destroy(io2);
	l_io_destroy(io1);

	assert(l_main_exit());
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("io", test_io, NULL);

	return l_test_run();
}

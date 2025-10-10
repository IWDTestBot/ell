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
#include <unistd.h>
#include <assert.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <ell/ell.h>

static void signal_handler(uint32_t signo, void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_info("Terminate");
		l_main_quit();
		break;
	}
}

static void timeout_quit_handler(struct l_timeout *timeout, void *user_data)
{
	l_main_quit();
}

static void idle_handler(struct l_idle *idle, void *user_data)
{
	static int count = 0;

	if ((count % 1000000) == 0)
		l_info("Idling...");

	count += 1;
}

static void oneshot_handler(void *user_data)
{
	l_info("One-shot");
}

static void race_delay_handler(struct l_timeout *timeout, void *user_data)
{
	l_info("Delay");
	usleep(250 * 1000);
}

static void race_handler(struct l_timeout *timeout, void *user_data)
{
	struct l_timeout **other_racer = user_data;

	l_info("Remove pending event");
	l_timeout_remove(*other_racer);
	*other_racer = NULL;
}

static void remove_handler(struct l_timeout *timeout, void *user_data)
{
	l_timeout_remove(timeout);
	l_info("Timer removed itself");
}

static void test_main(const void *data)
{
	struct l_timeout *timeout_quit;
	struct l_timeout *race_delay;
	struct l_timeout *race1;
	struct l_timeout *race2;
	struct l_timeout *remove_self;
	struct l_idle *idle;
	int exit_status;

	assert(l_main_init());

	timeout_quit = l_timeout_create(3, timeout_quit_handler, NULL, NULL);
	assert(timeout_quit);

	race_delay = l_timeout_create(1, race_delay_handler, NULL, NULL);
	race1 = l_timeout_create_ms(1100, race_handler, &race2, NULL);
	race2 = l_timeout_create_ms(1100, race_handler, &race1, NULL);
	assert(race_delay);
	assert(race1);
	assert(race2);

	remove_self = l_timeout_create(2, remove_handler, &remove_self, NULL);
	assert(remove_self);

	idle = l_idle_create(idle_handler, NULL, NULL);
	assert(idle);

	l_log_set_stderr();

	l_debug("hello");

#if (ULONG_MAX > UINT_MAX)
	l_debug("Checking timeout time limit");
	assert(!l_timeout_create_ms((UINT_MAX + 1UL) * 1000,
					timeout_quit_handler, NULL, NULL));
#endif

	l_idle_oneshot(oneshot_handler, NULL, NULL);

	exit_status = l_main_run_with_signal(signal_handler, NULL);
	assert(exit_status == EXIT_SUCCESS);

	l_timeout_remove(race_delay);
	l_timeout_remove(race1);
	l_timeout_remove(race2);

	l_timeout_remove(timeout_quit);

	l_idle_remove(idle);

	assert(l_main_exit());
}

static int sock_bind(const char *sock)
{
	struct sockaddr_un addr;
	socklen_t len;
	int fd;

	fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	assert(fd >= 0);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, sock, sizeof(addr.sun_path) - 1);
	len = offsetof(struct sockaddr_un, sun_path) + strlen(sock);

	if (addr.sun_path[0] == '@')
		addr.sun_path[0] = '\0';

	assert(!bind(fd, (struct sockaddr *) &addr, len));

	return fd;
}

static void test_sd_notify(const void *data)
{
	struct l_timeout *timeout_quit;
	char sock[] = "/tmp/ell-notify.XXXXXX";
	bool abstract = L_PTR_TO_INT(data);
	int exit_status;
	char buf[4096];
	int fd;

	/* Create a unique temporary path. */
	assert(!close(mkstemp(sock)));
	assert(!unlink(sock));

	if (abstract)
		sock[0] = '@';

	fd = sock_bind(sock);

	setenv("NOTIFY_SOCKET", sock, 1);
	setenv("WATCHDOG_USEC", "1000000", 1);

	assert(l_main_init());

	timeout_quit = l_timeout_create(1, timeout_quit_handler, NULL, NULL);
	assert(timeout_quit);

	exit_status = l_main_run_with_signal(signal_handler, NULL);
	assert(exit_status == EXIT_SUCCESS);

	assert(l_main_exit());

	assert(recv(fd, buf, sizeof(buf), MSG_TRUNC) == 7);
	assert(strncmp(buf, "READY=1", 7) == 0);

	assert(recv(fd, buf, sizeof(buf), MSG_TRUNC) == 10);
	assert(strncmp(buf, "WATCHDOG=1", 10) == 0);

	if (!abstract)
		unlink(sock);

	close(fd);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("main", test_main, NULL);
	l_test_add("sd_notify path", test_sd_notify, L_INT_TO_PTR(false));
	l_test_add("sd_notify abstract", test_sd_notify, L_INT_TO_PTR(true));

	return l_test_run();
}

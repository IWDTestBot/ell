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

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("main", test_main, NULL);

	return l_test_run();
}

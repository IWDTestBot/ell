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
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/prctl.h>

#include "log.h"
#include "main.h"
#include "idle.h"
#include "signal.h"
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

static pid_t test_pid = -1;

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

	if (debug_enable)
		l_debug_enable("*");
}

static void run_all_tests(void)
{
	struct test *test = test_head;

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
}

static void run_next_test(void *user_data)
{
	pid_t pid;

	if (!test_head) {
		l_main_quit();
		return;
	}

	if (!tap_enable)
		printf("TEST: %s\n", test_head->name);

	pid = fork();
	if (pid < 0) {
		perror("Failed to fork new process");
		l_main_quit();
		return;
	}

	if (pid == 0) {
		prctl(PR_SET_PDEATHSIG, SIGTERM);
		prctl(PR_SET_DUMPABLE, 0L);

		/* Close stdout to not interfere with TAP */
		close(STDOUT_FILENO);

		test_head->function(test_head->test_data);
		exit(EXIT_SUCCESS);
	}

	if (tap_enable && debug_enable)
		printf("# %d started\n", pid);

	test_pid = pid;
}

static void signal_handler(uint32_t signo, void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_info("Terminate");
		if (test_pid > 0) {
			l_info("Terminate test %d", test_pid);
			kill(SIGTERM, test_pid);
		}
		break;
	}
}

static void sigchld_handler(void *user_data)
{
	while (1) {
		pid_t pid;
		int wstatus;
		bool terminated = false;
		bool success;

		pid = waitpid(WAIT_ANY, &wstatus, WNOHANG);
		if (pid < 0 || pid == 0)
			break;

		if (WIFEXITED(wstatus)) {
			if (tap_enable && debug_enable)
				printf("# %d exited with status %d\n",
						pid, WEXITSTATUS(wstatus));
			terminated = true;
			success = !WEXITSTATUS(wstatus);
		} else if (WIFSIGNALED(wstatus)) {
			if (tap_enable && debug_enable)
				printf("# %d terminated with signal %d\n",
						pid, WTERMSIG(wstatus));
			terminated = true;
			success = false;
		}

		if (terminated && pid == test_pid) {
			struct test *test = test_head;

			test_pid = -1;

			if (tap_enable)
				printf("%sok %u - %s\n",
						success ? "" : "not ",
						test->num, test->name);

			test_head = test->next;
			free(test);

			if (!test_head)
				test_tail = NULL;

			l_idle_oneshot(run_next_test, NULL, NULL);
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
	struct l_signal *sigchld;
	int exit_status;

	if (tap_enable) {
		printf("TAP version 12\n");
		printf("1..%u\n", test_count);
	}

	if (cmd_list || uses_own_main) {
		run_all_tests();
		return EXIT_SUCCESS;
	}

	l_main_init();

	sigchld = l_signal_create(SIGCHLD, sigchld_handler, NULL, NULL);

	l_idle_oneshot(run_next_test, NULL, NULL);

	exit_status = l_main_run_with_signal(signal_handler, NULL);

	l_signal_remove(sigchld);

	l_main_exit();

	return exit_status;
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

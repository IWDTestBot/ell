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
#include <poll.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <sys/prctl.h>

#include "log.h"
#include "test.h"
#include "private.h"
#include "useful.h"

#ifndef WAIT_ANY
#define WAIT_ANY (-1) /* Any process */
#endif

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
static bool testing_active;
static int signal_fd;

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

static void show_tests(void)
{
	struct test *test = test_head;

	while (test) {
		struct test *tmp = test;

		printf("TEST: %s\n", test->name);

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
		testing_active = false;
		return;
	}

	if (!tap_enable)
		printf("TEST: %s\n", test_head->name);

	pid = fork();
	if (pid < 0) {
		perror("Failed to fork new process");
		testing_active = false;
		return;
	}

	if (pid == 0) {
		prctl(PR_SET_PDEATHSIG, SIGTERM);
		prctl(PR_SET_DUMPABLE, 0L);

		/* Don't keep the signalfd in the child process */
		close(signal_fd);

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

			run_next_test(NULL);
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
	sigset_t sig_mask, old_mask;
	int exit_status;

	if (cmd_list) {
		show_tests();
		return EXIT_SUCCESS;
	}

	if (tap_enable) {
		printf("TAP version 12\n");
		printf("1..%u\n", test_count);
	}

	sigemptyset(&sig_mask);
	sigaddset(&sig_mask, SIGINT);
	sigaddset(&sig_mask, SIGTERM);
	sigaddset(&sig_mask, SIGCHLD);

	/*
	 * Block signals so that they aren't handled according to their
	 * default dispositions.
	 */
	if (sigprocmask(SIG_BLOCK, &sig_mask, &old_mask) < 0)
		return EXIT_FAILURE;

	signal_fd = signalfd(-1, &sig_mask, SFD_CLOEXEC);
	if (signal_fd < 0) {
		sigprocmask(SIG_SETMASK, &old_mask, NULL);
		return EXIT_FAILURE;
	}

	exit_status = EXIT_SUCCESS;
	testing_active = true;

	run_next_test(NULL);

	while (testing_active) {
		struct pollfd fds[1];
		struct signalfd_siginfo ssi;
		ssize_t result;
		int res;

		fds[0].fd = signal_fd;
		fds[0].events = POLLIN;
		fds[0].revents = 0;

		res = poll(fds, 1, -1);
		if (res < 0) {
			exit_status = EXIT_FAILURE;
			break;
		}

		if (res == 0)
			continue;

		result = read(signal_fd, &ssi, sizeof(ssi));
		if (result != sizeof(ssi))
			continue;

		switch (ssi.ssi_signo) {
		case SIGINT:
		case SIGTERM:
			signal_handler(ssi.ssi_signo, NULL);
			break;
		case SIGCHLD:
			sigchld_handler(NULL);
			break;
		}
	}

	close(signal_fd);

	sigprocmask(SIG_SETMASK, &old_mask, NULL);

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

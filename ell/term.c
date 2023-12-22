/*
 * Embedded Linux library
 * Copyright (C) 2023  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>

#include "private.h"
#include "signal.h"
#include "io.h"
#include "term.h"

struct term_ops {
	bool color_support;
	bool use_sigwinch;
	int (*get_winsize) (int fd, unsigned short *row, unsigned short *col);
	int (*get_attr) (int fd, struct termios *c);
	int (*set_attr) (int fd, const struct termios *c);
};

static int null_get_winsize(int fd, unsigned short *row, unsigned short *col)
{
	if (row) *row = 24;
	if (col) *col = 80;
	return 0;
}

static int null_get_attr(int fd, struct termios *c)
{
	return 0;
}

static int null_set_attr(int fd, const struct termios *c)
{
	return 0;
}

static const struct term_ops default_null_ops = {
	.color_support	= false,
	.use_sigwinch	= false,
	.get_winsize	= null_get_winsize,
	.get_attr	= null_get_attr,
	.set_attr	= null_set_attr,
};

static int tty_get_winsize(int fd, unsigned short *row, unsigned short *col)
{
	struct winsize ws;
	int res;

	res = ioctl(fd, TIOCGWINSZ, &ws);
	if (!res) {
		if (row) *row = ws.ws_row;
		if (col) *col = ws.ws_col;
	}
	return res;
}

static int tty_get_attr(int fd, struct termios *c)
{
	return tcgetattr(fd, c);
}

static int tty_set_attr(int fd, const struct termios *c)
{
	return tcsetattr(fd, TCSANOW, c);
}

static const struct term_ops default_tty_ops = {
	.color_support	= true,
	.use_sigwinch	= true,
	.get_winsize	= tty_get_winsize,
	.get_attr	= tty_get_attr,
	.set_attr	= tty_set_attr,
};

struct l_term {
	int in_fd;
	int out_fd;
	const struct term_ops *in_ops;
	const struct term_ops *out_ops;
	struct termios in_termios;
	struct termios out_termios;
	unsigned short num_row;
	unsigned short num_col;
	struct l_signal *sigwinch;
	struct l_io *in_io;
	bool is_running;
	char key_buf[8];
	size_t key_len;
	l_term_key_func_t key_handler;
	void *key_data;
};

LIB_EXPORT struct l_term *l_term_new(void)
{
	struct l_term *term;

	term = l_new(struct l_term, 1);

	term->in_fd = -1;
	term->in_ops = NULL;

	term->out_fd = -1;
	term->out_ops = NULL;

	term->is_running = false;

	return term;
}

LIB_EXPORT void l_term_free(struct l_term *term)
{
	if (!term)
		return;

	l_free(term);
}

static bool set_input(struct l_term *term, int fd)
{
	if (!term)
		return false;

	term->in_fd = fd;
	term->in_ops = NULL;

	return true;
}

static bool set_output(struct l_term *term, int fd)
{
	if (!term)
		return false;

	term->out_fd = fd;
	term->out_ops = NULL;

	return true;
}

LIB_EXPORT bool l_term_set_input_stdin(struct l_term *term)
{
	return set_input(term, STDIN_FILENO);
}

LIB_EXPORT bool l_term_set_output_stdout(struct l_term *term)
{
	return set_output(term, STDOUT_FILENO);
}

LIB_EXPORT bool l_term_set_key_handler(struct l_term *term,
				l_term_key_func_t handler, void *user_data)
{
	if (!term)
		return false;

	term->key_handler = handler;
	term->key_data = user_data;

	return true;
}

static bool in_callback(struct l_io *io, void *user_data)
{
	struct l_term *term = user_data;
	wchar_t wstr[2];
	ssize_t len;

	len = read(term->in_fd, term->key_buf + term->key_len,
					sizeof(term->key_buf) - term->key_len);
	if (len < 0)
		return true;

	term->key_len += len;

	while (term->key_len > 0) {
		len = mbtowc(wstr, term->key_buf, term->key_len);
		if (len < 0)
			break;

		memmove(term->key_buf, term->key_buf + len,
						term->key_len - len);
		term->key_len -= len;

		if (term->key_handler) {
			wint_t wch = wstr[0];
			term->key_handler(wch, term->key_data);
		}
	}

	return true;
}

static void sigwinch_handler(void *user_data)
{
	struct l_term *term = user_data;

	term->out_ops->get_winsize(term->out_fd,
					&term->num_row, &term->num_col);
}

LIB_EXPORT bool l_term_open(struct l_term *term)
{
	struct termios termios;

	if (!term)
		return false;

	/* Missing input or output file descriptor is a non-recoverable
	 * situation at this point.
	 */
	if (term->in_fd < 0 || term->out_fd < 0)
		return false;

	/* If no input operations are provided, fallback to use TTY
	 * defaults or null setting.
	 */
	if (!term->in_ops) {
		if (isatty(term->in_fd))
			term->in_ops = &default_tty_ops;
		else
			term->in_ops = &default_null_ops;
	}

	/* If no output operations are provided, fallback to use TTY
	 * defaults or null setting.
	 */
	if (!term->out_ops) {
		if (isatty(term->out_fd))
			term->out_ops = &default_tty_ops;
		else
			term->out_ops = &default_null_ops;
	}

	/* Save current termios setting of input */
	memset(&term->in_termios, 0, sizeof(term->in_termios));
	term->in_ops->get_attr(term->in_fd, &term->in_termios);

	/* Save current termios setting of output */
	memset(&term->out_termios, 0, sizeof(term->out_termios));
	term->out_ops->get_attr(term->out_fd, &term->out_termios);

	/* Disable canonical mode (ICANON), disable echoing of input
	 * characters (ECHO) and disable generating signals.
	 *
	 * In noncanonical mode input is available immediately (without
	 * the user having to type a line-delimiter character), no input
	 * processing is performed, and line editing is disabled.
	 *
	 * When any of the characters INTR, QUIT, SUSP, or DSUSP are
	 * received, don't generate the corresponding signal.
	 */
	memcpy(&termios, &term->in_termios, sizeof(termios));
	termios.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG);
	term->in_ops->set_attr(term->in_fd, &termios);

	/* Send TIOCGWINSZ ioctl to retrieve col and row number */
	term->out_ops->get_winsize(term->out_fd,
					&term->num_row, &term->num_col);

	/* Setup SIGWINCH window resize signal handler if supported */
	if (term->out_ops->use_sigwinch)
		term->sigwinch = l_signal_create(SIGWINCH, sigwinch_handler,
								term, NULL);

	term->in_io = l_io_new(term->in_fd);
	l_io_set_read_handler(term->in_io, in_callback, term, NULL);

	term->is_running = true;

	return true;
}

LIB_EXPORT bool l_term_close(struct l_term *term)
{
	if (!term)
		return false;

	term->is_running = false;

	l_io_destroy(term->in_io);

	/* Remove SIGWINCH window resize signal handler */
	if (term->out_ops->use_sigwinch)
		l_signal_remove(term->sigwinch);

	/* Restore previous termios setting from input and output */
	term->in_ops->set_attr(term->in_fd, &term->in_termios);
	term->out_ops->set_attr(term->out_fd, &term->out_termios);

	return true;
}

LIB_EXPORT bool l_term_putnstr(struct l_term *term, const char *str, size_t n)
{
	ssize_t res;

	if (!term)
		return false;

	if (!term->is_running)
		return false;

	res = write(term->out_fd, str, n);
	if (res < 0)
		return false;

	return true;
}

LIB_EXPORT bool l_term_putstr(struct l_term *term, const char *str)
{
	if (!str)
		return false;
	return l_term_putnstr(term, str, strlen(str));
}

LIB_EXPORT bool l_term_putchar(struct l_term *term, int ch)
{
	char c = ch;
	return l_term_putnstr(term, &c, 1);
}

LIB_EXPORT bool l_term_get_max_columns(struct l_term *term, unsigned short *num)
{
	if (!term)
		return false;

	if (!term->out_ops)
		return false;

	if (term->out_ops->get_winsize(term->out_fd, NULL, num) < 0)
		return false;

	return true;
}

/*
 * Embedded Linux library
 * Copyright (C) 2023-2024  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>

#include "private.h"
#include "signal.h"
#include "io.h"
#include "term.h"

// MARK: Preprocessor Definitions

#define IO_HANDLER(term, fd, readable, writable) \
	do {										 \
		if (term && term->io_handler) {			 \
			term->io_handler(term,				 \
							 fd,				 \
							 readable,			 \
							 writable,			 \
							 term->io_data);	 \
		}										 \
	} while (0)

// MARK: Type Declarations

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
	.get_attr		= null_get_attr,
	.set_attr		= null_set_attr,
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
	else
		res = -errno;

	return res;
}

static int tty_get_attr(int fd, struct termios *c)
{
	int retval = 0;

	if (tcgetattr(fd, c) != 0)
		retval = -errno;

	return retval;
}

static int tty_set_attr(int fd, const struct termios *c)
{
	int retval = 0;

	if (tcsetattr(fd, TCSANOW, c) != 0)
		retval = -errno;

	return retval;
}

static const struct term_ops default_tty_ops = {
	.color_support	= true,
	.use_sigwinch	= true,
	.get_winsize	= tty_get_winsize,
	.get_attr		= tty_get_attr,
	.set_attr		= tty_set_attr,
};

struct l_term {
	int in_fd;
	int out_fd;
	l_term_io_func_t io_handler;
	void *io_data;
	const struct term_ops *in_ops;
	const struct term_ops *out_ops;
	struct termios in_termios;
	struct termios out_termios;
	unsigned short num_row;
	unsigned short num_col;
	struct l_signal *sigwinch;
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

LIB_EXPORT int l_term_set_io_handler(struct l_term *term,
				l_term_io_func_t handler, void *user_data)
{
	if (!term)
		return -EINVAL;

	term->io_handler = handler;
	term->io_data = user_data;

	return 0;
}

LIB_EXPORT int l_term_set_input(struct l_term *term, int fd)
{
	if (!term)
		return -EINVAL;

	if (fd < 0)
		return -EBADF;

	term->in_fd = fd;
	term->in_ops = NULL;

	IO_HANDLER(term, fd, 1, 0);

	return 0;
}

LIB_EXPORT int l_term_set_output(struct l_term *term, int fd)
{
	if (!term)
		return -EINVAL;

	if (fd < 0)
		return -EBADF;

	term->out_fd = fd;
	term->out_ops = NULL;

	IO_HANDLER(term, fd, 0, 1);

	return 0;
}

LIB_EXPORT int l_term_set_input_stdin(struct l_term *term)
{
	return l_term_set_input(term, STDIN_FILENO);
}

LIB_EXPORT int l_term_set_output_stdout(struct l_term *term)
{
	return l_term_set_output(term, STDOUT_FILENO);
}

LIB_EXPORT int l_term_set_key_handler(struct l_term *term,
				l_term_key_func_t handler, void *user_data)
{
	if (!term)
		return -EINVAL;

	term->key_handler = handler;
	term->key_data = user_data;

	return 0;
}

LIB_EXPORT bool l_term_io_callback(struct l_io *io, void *user_data)
{
	struct l_term *term = user_data;

	l_term_process(term);

	return true;
}

static void sigwinch_handler(void *user_data)
{
	struct l_term *term = user_data;

	term->out_ops->get_winsize(term->out_fd,
					&term->num_row, &term->num_col);
}

LIB_EXPORT int l_term_open(struct l_term *term)
{
	struct termios termios;
	int retval = 0;

	if (!term)
		return -EINVAL;

	/* Missing input or output file descriptor is a non-recoverable
	 * situation at this point.
	 */
	if (term->in_fd < 0 || term->out_fd < 0)
		return -EBADF;

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
	retval = term->in_ops->get_attr(term->in_fd, &term->in_termios);
	if (retval < 0)
		return retval;

	/* Save current termios setting of output */
	memset(&term->out_termios, 0, sizeof(term->out_termios));
	retval = term->out_ops->get_attr(term->out_fd, &term->out_termios);
	if (retval < 0)
		return retval;

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
	retval = term->in_ops->set_attr(term->in_fd, &termios);
	if (retval < 0)
		return retval;

	/* Send TIOCGWINSZ ioctl to retrieve col and row number */
	retval = term->out_ops->get_winsize(term->out_fd,
					&term->num_row, &term->num_col);
	if (retval < 0)
		return retval;

	/* Setup SIGWINCH window resize signal handler if supported */
	if (term->out_ops->use_sigwinch)
		term->sigwinch = l_signal_create(SIGWINCH, sigwinch_handler,
								term, NULL);

	IO_HANDLER(term, term->in_fd, 1, 0);
	IO_HANDLER(term, term->out_fd, 0, 1);

	term->is_running = true;

	return retval;
}

LIB_EXPORT int l_term_close(struct l_term *term)
{
	int retval = 0;

	if (!term)
		return -EINVAL;

	term->is_running = false;

	IO_HANDLER(term, term->in_fd, 0, 0);
	IO_HANDLER(term, term->out_fd, 0, 0);

	/* Remove SIGWINCH window resize signal handler */
	if (term->out_ops->use_sigwinch)
		l_signal_remove(term->sigwinch);

	/* Restore previous termios setting from input and output */
	retval = term->in_ops->set_attr(term->in_fd, &term->in_termios);
	if (retval < 0)
		return retval;

	retval = term->out_ops->set_attr(term->out_fd, &term->out_termios);
	if (retval < 0)
		return retval;

	return retval;
}

LIB_EXPORT void l_term_process(struct l_term *term)
{
	wchar_t wstr[2];
	ssize_t len;
	mbstate_t ps;

	if (!term)
		return;

	len = read(term->in_fd, term->key_buf + term->key_len,
					sizeof(term->key_buf) - term->key_len);
	if (len < 0)
		return;

	term->key_len += len;

	while (term->key_len > 0) {
		memset(&ps, 0, sizeof(ps));

		len = mbrtowc(wstr, term->key_buf, term->key_len, &ps);
		if (len < 0)
			break;

		memmove(term->key_buf, term->key_buf + len,
						term->key_len - len);
		term->key_len -= len;

		if (term->key_handler) {
			wint_t wch = wstr[0];
			term->key_handler(term, wch, term->key_data);
		}
	}
}

LIB_EXPORT int l_term_putnstr(struct l_term *term, const char *str, size_t n)
{
	ssize_t res;

	if (!term)
		return -EINVAL;

	if (term->out_fd < 0)
		return -EBADF;

	res = write(term->out_fd, str, n);
	if (res < 0)
		return -errno;

	return 0;
}

LIB_EXPORT int l_term_putstr(struct l_term *term, const char *str)
{
	if (!str)
		return -EINVAL;

	return l_term_putnstr(term, str, strlen(str));
}

LIB_EXPORT int l_term_putchar(struct l_term *term, int ch)
{
	char c = ch;

	return l_term_putnstr(term, &c, 1);
}

LIB_EXPORT int l_term_print(struct l_term *term, const char *str, ...)
{
	va_list ap;
	int retval;

	va_start(ap, str);

	retval = l_term_vprint(term, str, ap);

	va_end(ap);

	return retval;
}

LIB_EXPORT int l_term_vprint(struct l_term *term, const char *str, va_list ap)
{
	if (!term || !str)
		return -EINVAL;

	if (term->out_fd < 0)
		return -EBADF;

	if (vdprintf(term->out_fd, str, ap) < 0)
		return -errno;

	return 0;
}

LIB_EXPORT int l_term_set_bounds(struct l_term *term, uint16_t rows,
				uint16_t columns)
{
	if (!term)
		return -EINVAL;

	term->num_row = rows;
	term->num_col = columns;

	return 0;
}

LIB_EXPORT int l_term_get_rows(struct l_term *term, uint16_t *rows)
{
	int retval = 0;

	if (!term)
		return -EINVAL;

	if (!term->out_ops)
		return -ENOSYS;

	retval = term->out_ops->get_winsize(term->out_fd, rows, NULL);

	return retval;
}

LIB_EXPORT int l_term_get_columns(struct l_term *term, uint16_t *columns)
{
	int retval = 0;

	if (!term)
		return -EINVAL;

	if (!term->out_ops)
		return -ENOSYS;

	retval = term->out_ops->get_winsize(term->out_fd, NULL, columns);

	return retval;
}

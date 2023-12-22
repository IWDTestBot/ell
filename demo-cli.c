/*
 * Embedded Linux library
 * Copyright (C) 2023  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <locale.h>
#include <langinfo.h>
#include <ell/ell.h>

#define ENCODING_UTF8	"UTF-8"

static struct l_term *term;
static struct l_edit *edit;
static const char *history_pathname = "history.txt";

static const char *prompt = "hello> ";
static size_t prompt_len = 7;

static void display_handler(const wchar_t *wstr, size_t wlen,
						size_t pos, void *user_data)
{
	size_t i;
	char *mb_buf;
	size_t mb_size;
	size_t mb_len;
	mbstate_t ps;

	memset(&ps, 0, sizeof(ps));
	mb_size = wcstombs(NULL, wstr, 0) + 1;
	mb_buf = l_malloc(mb_size);
	mb_len = wcsnrtombs(mb_buf, &wstr, wlen, mb_size, &ps);

	l_term_putchar(term, '\r');
	l_term_putnstr(term, prompt, prompt_len);
	l_term_putnstr(term, mb_buf, mb_len);
	l_term_putnstr(term, "\033[K", 3);

	for (i = wlen; i > pos; i--)
		l_term_putchar(term, '\b');

	l_free(mb_buf);
}

static void handle_input(wint_t wch)
{
	static enum {
		IN_DEFAULT,
		IN_ESC,
		IN_SS2,
		IN_SS3,
		IN_CSI,
	} in_state = IN_DEFAULT;
	static char csi_p_str[5];
	static unsigned int csi_p_pos;
	char *line;

	switch (in_state) {
	case IN_DEFAULT:
		switch (wch) {
		case 0:		/* NUL - Null (^@) (\0) */
			break;
		case 1:		/* SOH - Start of Heading (^A) */
			l_edit_move_home(edit);
			break;
		case 2:		/* STX - Start of Text (^B) */
			l_edit_move_left(edit);
			break;
		case 3:		/* ETX - End of Text (^C) */
			l_term_putnstr(term, "^C\n", 3);
			l_edit_reset(edit, NULL);
			break;
		case 4:		/* EOT - End of Transmit (^D) */
			if (l_edit_is_empty(edit)) {
				l_edit_history_save(edit, history_pathname);
				l_term_putnstr(term, "\r\n", 2);
				l_main_quit();
			} else {
				l_edit_delete(edit);
			}
			break;
		case 5:		/* ENQ - Enquiry (^E) */
			l_edit_move_end(edit);
			break;
		case 6:		/* ACK - Acknowledgement (^F) */
			l_edit_move_right(edit);
			break;
		case 7:		/* BEL - Acknowledgement (^G) (\a) */
			break;
		case 8:		/* BS - Backspace (^H) (\b) */
			l_edit_backspace(edit);
			break;
		case 9:		/* HT - Horizontal Tab (^I) (\t) */
			break;
		case 10:	/* LF - Line Feed (^J) (\n) */
			l_edit_move_end(edit);
			l_term_putchar(term, '\n');
			line = l_edit_enter(edit);
			l_free(line);
			break;
		case 11:	/* VT - Vertial Tab (^K) (\v) */
			l_edit_truncate(edit);
			break;
		case 12:	/* FF - Form Feed (^L) (\f) */
			l_term_putstr(term, "\033[H\033[2J");
			l_edit_refresh(edit);
			break;
		case 13:	/* CR - Carriage Return (^M) (\r) */
			break;
		case 14:	/* SO - Shift Out (^N) */
			l_edit_history_forward(edit);
			break;
		case 15:	/* SI - Shift In (^O) */
			break;
		case 16:	/* DLE - Data Link Escape (^P) */
			l_edit_history_backward(edit);
			break;
		case 17 ... 20:
			break;
		case 21:	/* NAK - Negative Acknowledgement (^U) */
			l_edit_delete_all(edit);
			break;
		case 22:	/* SYN - Synchronous Idle (^V) */
			break;
		case 23:	/* ETB - End of Transmission Block (^W) */
			break;
		case 24:	/* CAN - Cancel (^X) */
			break;
		case 25:	/* EM - End of Medium (^Y) */
			break;
		case 26:	/* SUB - Substitute (^Z) */
			break;
		case 27:	/* ESC - Escape (^[) (\e) */
			in_state = IN_ESC;
			break;
		case 28 ... 31:
			break;
		case 32 ... 126:
			l_edit_insert(edit, wch);
			break;
		case 127:	/* DEL - Delete (^?) */
			l_edit_backspace(edit);
			break;
		case 155:	/* CSI - Control Sequence Introducer */
			in_state = IN_CSI;
			memset(csi_p_str, '\0', sizeof(csi_p_str));
			csi_p_pos = 0;
			break;
		default:
			l_edit_insert(edit, wch);
			break;
		}
		break;

	case IN_ESC:
		/* ESC   1/11         Escape
		 * I...I 2/0 to 2/15  Intermediate (zero or more characters)
		 * F     3/0 to 7/14  Final (one character)
		 */
		switch (wch) {
		case 0 ... 31:
			in_state = IN_DEFAULT;
			break;
		case 32 ... 47:		/* Intermediate */
			break;
		case 48 ... 126:	/* Final */
			switch (wch) {
			case 'b':
				/* Word left */
				in_state = IN_DEFAULT;
				break;
			case 'f':
				/* Word right */
				in_state = IN_DEFAULT;
				break;
			case 'N':	/* SS2 - Single Shift G2 */
				in_state = IN_SS2;
				break;
			case 'O':	/* SS3 - Single Shift G3 */
				in_state = IN_SS3;
				break;
			case '[':	/* CSI - Control Sequence Introducer */
				in_state = IN_CSI;
				memset(csi_p_str, '\0', sizeof(csi_p_str));
				csi_p_pos = 0;
				break;
			default:
				in_state = IN_DEFAULT;
				break;
			}
			break;
		case 127:
			in_state = IN_DEFAULT;
			break;
		}
		break;

	case IN_SS2:
		/* SS2   4/14 Single Shift G2
		 */
		in_state = IN_DEFAULT;
		break;

	case IN_SS3:
		/* SS3   4/15 Single Shift G3
		 */
		in_state = IN_DEFAULT;
		break;

	case IN_CSI:
		/* CSI   9/11         Control sequence introducer
		 * I...I 2/0 to 2/15  Intermediate (zero or more characters)
		 * P...P 3/0 to 3/15  Parameter (zero or more characters)
		 * F     4/0 to 7/14  Final (one character)
		 */
		switch (wch) {
		case 0 ... 31:
			in_state = IN_DEFAULT;
			break;
		case 32 ... 47:		/* Intermediate */
			break;
		case 48 ... 63:		/* Parameter */
			if (csi_p_pos < sizeof(csi_p_str) - 1)
				csi_p_str[csi_p_pos++] = wch;
			break;
		case 64 ... 126:	/* Final */
			switch (wch) {
			case 'A':	/* CUU - Cursor Up */
				l_edit_history_backward(edit);
				break;
			case 'B':	/* CUD - Cursor Down */
				l_edit_history_forward(edit);
				break;
			case 'C':	/* CUF - Cursor Forward */
				l_edit_move_right(edit);
				break;
			case 'D':	/* CUB - Cursor Back */
				l_edit_move_left(edit);
				break;
			case 'F':
				l_edit_move_end(edit);
				break;
			case 'H':
				l_edit_move_home(edit);
				break;
			case '~':
				if (!strcmp(csi_p_str, "3")) {
					/* Delete */
					l_edit_delete(edit);
				} else if (!strcmp(csi_p_str, "5")) {
					/* PgUp */
				} else if (!strcmp(csi_p_str, "6")) {
					/* PgDn */
				}
				break;
			}
			in_state = IN_DEFAULT;
			break;
		case 127:
			in_state = IN_DEFAULT;
			break;
		}
		break;
	}
}

static void key_handler(wint_t wch, void *user_data)
{
	handle_input(wch);
}

int main(int argc, char *argv[])
{
	unsigned short num_col = 80;
	int exit_status;

	setlocale(LC_ALL, "");
	if (strcmp(nl_langinfo(CODESET), ENCODING_UTF8)) {
		fprintf(stderr, "no %s\n", ENCODING_UTF8);
		return EXIT_FAILURE;
	}

	l_main_init();

	term = l_term_new();
	l_term_set_input_stdin(term);
	l_term_set_output_stdout(term);

	edit = l_edit_new();
	l_edit_set_history_size(edit, 100);
	l_edit_history_load(edit, history_pathname);

	l_term_open(term);

	l_term_set_key_handler(term, key_handler, NULL);
	l_term_get_max_columns(term, &num_col);

	l_edit_set_max_display_length(edit, num_col - prompt_len);
	l_edit_set_display_handler(edit, display_handler, NULL);

	exit_status = l_main_run();

	l_term_close(term);

	l_edit_free(edit);

	l_term_free(term);

	l_main_exit();

	return exit_status;
}

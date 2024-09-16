/*
 * Embedded Linux library
 * Copyright (C) 2023  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _XOPEN_SOURCE_EXTENDED
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <locale.h>
#include <langinfo.h>
#include <curses.h>
#include <wctype.h>
#include <time.h>
#include <ell/ell.h>

#define ENCODING_UTF8	"UTF-8"

#define UPDATE_RATE (5)

static struct l_edit *edit;

#define last_key_str_size (20)
static wchar_t last_key_str[last_key_str_size] = L"";
static int curs_visibility = 0;
static bool show_time = false;
static bool masked_input = false;

static short prompt_color[] = { 1, 6, 7 };
static const char *prompt_list[] = { "hello> ", "fun> ", "long-prompt> " };
static unsigned int prompt_idx = 0;

static int main_size_list[] = { 50, 70 };
static unsigned int main_size_idx = 0;

static size_t input_len_list[] = { 0, 12, 20 };
static unsigned int input_len_idx = 0;

static unsigned int history_size_list[] = { 100, 0, 15, 10 };
static unsigned int history_size_idx = 0;

static const char *history_pathname = "history.txt";
static const char *history_alt_pathname = "history-alt.txt";

static WINDOW *main_win;
static WINDOW *info_win;
static WINDOW *status_win;
static WINDOW *command_win;

static void set_cursor(void)
{
	curs_set(curs_visibility);

	if (curs_visibility)
		leaveok(stdscr, FALSE);
	else
		leaveok(stdscr, TRUE);
}

static const char *help_str[] = {
	"Ctrl-Q  Load alternate history",
	"Ctrl-R  Set sample input",
	"Ctrl-S  Set history size",
	"Ctrl-T  Switch time printouts",
	"Ctrl-V  Set max input length",
	"Ctrl-W  Set window size",
	"Ctrl-X  Switch prompt",
	"Ctrl-Z  Masked input",
	NULL
};

static void update_debug(void)
{
	int x, y, max_y, max_x;
	unsigned int i;

	getyx(main_win, y, x);
	getmaxyx(stdscr, max_y, max_x);

	wmove(info_win, 0, 0);
	wprintw(info_win, "(%d,%d) [%d,%d]   ", x, y, max_x, max_y);
	waddwstr(info_win, last_key_str);
	wclrtoeol(info_win);

	getmaxyx(info_win, max_y, max_x);

	wmove(info_win, 2, 0);
	for (i = 0; help_str[i]; i++) {
		waddnstr(info_win, help_str[i], max_x - 1);
		waddch(info_win, '\n');
	}

	wnoutrefresh(info_win);
	wnoutrefresh(main_win);
	doupdate();
}

static void resize_display(void)
{
	int main_size = main_size_list[main_size_idx];
	const char *prompt = prompt_list[prompt_idx];
	size_t prompt_len;
	int height, width;

	getmaxyx(stdscr, height, width);

	wresize(main_win, height - 2, main_size);
	mvwin(main_win, 0, 0);

	wresize(info_win, height - 2, width - main_size);
	mvwin(info_win, 0, main_size);

	wresize(status_win, 1, width);
	mvwin(status_win, height - 2, 0);

	wresize(command_win, 1, width);
	mvwin(command_win, height - 1, 0);

	wnoutrefresh(main_win);
	wnoutrefresh(info_win);
	wnoutrefresh(status_win);
	wnoutrefresh(command_win);

	prompt_len = strlen(prompt);
	l_edit_set_max_display_length(edit, getmaxx(main_win) - prompt_len);

	update_debug();
}

static void init_display(void)
{
	setlocale(LC_ALL, "");
	if (strcmp(nl_langinfo(CODESET), ENCODING_UTF8))
		printf("no %s\n", ENCODING_UTF8);

	initscr();
	nonl();
	cbreak();
	raw();
	noecho();
	use_extended_names(TRUE);

	start_color();
	use_default_colors();
	init_extended_pair(1, COLOR_BLACK, -1);
	init_pair(2, COLOR_BLACK, COLOR_WHITE);
	init_pair(3, COLOR_WHITE, COLOR_BLUE);
	init_extended_pair(6, COLOR_BLUE, -1);
	init_extended_pair(7, COLOR_RED, -1);

	main_win = newwin(1, 1, 0, 0);
	info_win = newwin(1, 1, 0, 1);
	status_win = newwin(1, 2, 1, 0);
	command_win = newwin(1, 2, 2, 0);

	wbkgdset(main_win, COLOR_PAIR(1));
	wbkgdset(info_win, COLOR_PAIR(2));
	wbkgdset(status_win, COLOR_PAIR(3));
	wattrset(status_win, A_BOLD);
	wbkgdset(command_win, COLOR_PAIR(1));

	wclear(main_win);
	wclear(info_win);
	wclear(status_win);
	wclear(command_win);
	wmove(main_win, 0, 0);

	keypad(main_win, TRUE);
	meta(main_win, TRUE);
	nodelay(main_win, TRUE);
	scrollok(main_win, TRUE);

	set_cursor();
}

static void reset_display(void)
{
	curs_set(1);
	endwin();
}

static void update_status(void)
{
	wmove(status_win, 0, 0);
	wprintw(status_win, "Hello %s", "Curses Demo");
	wclrtoeol(status_win);

	wnoutrefresh(status_win);
	wnoutrefresh(main_win);
	doupdate();
}

static void update_callback(struct l_timeout *timeout, void *user_data)
{
	if (show_time) {
		time_t rawtime;
		struct tm *tm;
		char str[80];
		int y;

		wmove(main_win, getcury(main_win), 0);
		wclrtoeol(main_win);

		time(&rawtime);
		tm = localtime(&rawtime);

		strftime(str, sizeof(str), "%H:%M:%S", tm);
		y = getcury(main_win);
		mvwprintw(main_win, y, 0, "Time is %s\n", str);
		wrefresh(main_win);

		l_edit_refresh(edit);
	}

	l_timeout_modify(timeout, UPDATE_RATE);
}

static void handle_keycode(wint_t keycode)
{
	char *line;

	switch (keycode) {
	case KEY_DOWN:			/* down-arrow key */
		l_edit_history_forward(edit);
		break;
	case KEY_UP:			/* up-arrow key */
		l_edit_history_backward(edit);
		break;
	case KEY_LEFT:			/* left-arrow key */
		l_edit_move_left(edit);
		break;
	case KEY_RIGHT:			/* right-arrow key */
		l_edit_move_right(edit);
		break;
	case KEY_HOME:			/* home key */
		l_edit_move_home(edit);
		break;
	case KEY_BACKSPACE:		/* backspace key */
		l_edit_backspace(edit);
		break;
	case KEY_DL:			/* delete-line key */
		l_edit_delete_all(edit);
		break;
	case KEY_DC:			/* delete-character key */
		l_edit_delete(edit);
		break;
	case KEY_CLEAR:			/* clear-screen or erase key */
		wclear(main_win);
		l_edit_refresh(edit);
		break;
	case KEY_EOL:			/* clear-to-end-of-line key */
		l_edit_truncate(edit);
		break;
	case KEY_ENTER:			/* enter/send key */
		l_edit_move_end(edit);
		waddch(main_win, '\n');
		line = l_edit_enter(edit);
		l_free(line);
		break;
	case KEY_RESET:			/* Reset or hard reset (unreliable) */
		waddstr(main_win, "^C\n");
		l_edit_reset(edit, NULL);
		break;
	case KEY_BTAB:			/* back-tab key */
		break;
	case KEY_END:			/* end key */
		l_edit_move_end(edit);
		break;
	case KEY_RESIZE:		/* Terminal resize event */
		resize_display();
		break;
	}
}

static void handle_cntrl(wint_t wch)
{
	switch (wch) {
	case 1:		/* Ctrl-A */
		handle_keycode(KEY_HOME);
		break;
	case 2:		/* Ctrl-B */
		handle_keycode(KEY_LEFT);
		break;
	case 3:		/* Ctrl-C */
		handle_keycode(KEY_RESET);
		break;
	case 4:		/* Ctrl-D */
		if (l_edit_is_empty(edit)) {
			l_edit_history_save(edit, history_pathname);
			l_main_quit();
		} else {
			handle_keycode(KEY_DC);
		}
		break;
	case 5:		/* Ctrl-E */
		handle_keycode(KEY_END);
		break;
	case 6:		/* Ctrl-F */
		handle_keycode(KEY_RIGHT);
		break;
	case 7:		/* Ctrl-G */
		break;
	case 8:		/* Ctrl-H */
		handle_keycode(KEY_BACKSPACE);
		break;
	case 9:		/* Ctrl-I */
		break;
	case 10:	/* Ctrl-J */
		break;
	case 11:	/* Ctrl-K */
		handle_keycode(KEY_EOL);
		break;
	case 12:	/* Ctrl-L */
		handle_keycode(KEY_CLEAR);
		break;
	case 13:	/* Ctrl-M */
		handle_keycode(KEY_ENTER);
		break;
	case 14:	/* Ctrl-N */
		handle_keycode(KEY_DOWN);
		break;
	case 15:	/* Ctrl-O */
		break;
	case 16:	/* Ctrl-P */
		handle_keycode(KEY_UP);
		break;
	case 17:	/* Ctrl-Q */
		l_edit_history_load(edit, history_alt_pathname);
		break;
	case 18:	/* Ctrl-R */
		l_edit_reset(edit, "Sample input string");
		break;
	case 19:	/* Ctrl-S */
		history_size_idx++;
		if (history_size_idx >= L_ARRAY_SIZE(history_size_list))
			history_size_idx = 0;
		l_edit_set_history_size(edit,
					history_size_list[history_size_idx]);
		break;
	case 20:	/* Ctrl-T */
		show_time = !show_time;
		break;
	case 21:	/* Ctrl-U */
		handle_keycode(KEY_DL);
		break;
	case 22:	/* Ctrl-V */
		input_len_idx++;
		if (input_len_idx >= L_ARRAY_SIZE(input_len_list))
			input_len_idx = 0;
		l_edit_set_max_input_length(edit,
					input_len_list[input_len_idx]);
		break;
	case 23:	/* Ctrl-W */
		main_size_idx++;
		if (main_size_idx >= L_ARRAY_SIZE(main_size_list))
			main_size_idx = 0;
		resize_display();
		break;
	case 24:	/* Ctrl-X */
		prompt_idx++;
		if (prompt_idx >= L_ARRAY_SIZE(prompt_list))
			prompt_idx = 0;
		resize_display();
		break;
	case 25:	/* Ctrl-Y */
		curs_visibility = !curs_visibility;
		set_cursor();
		l_edit_refresh(edit);
		break;
	case 26:	/* Ctrl-Z */
		masked_input = !masked_input;
		l_edit_refresh(edit);
		break;
	}
}

static void handle_print(wint_t wch)
{
	l_edit_insert(edit, wch);
}

static bool stdin_callback(struct l_io *io, void *user_data)
{
	wint_t wch;

	switch (wget_wch(main_win, &wch)) {
	case OK:
		if (iswcntrl(wch)) {
			swprintf(last_key_str, last_key_str_size,
						L"%s (%d)", unctrl(wch), wch);
			update_debug();
			handle_cntrl(wch);
		} else if (iswprint(wch)) {
			swprintf(last_key_str, last_key_str_size,
						L"%lc (%d)", wch, wch);
			update_debug();
			handle_print(wch);
		}
		break;
	case KEY_CODE_YES:
		if (wch >= KEY_MIN) {
			swprintf(last_key_str, last_key_str_size,
						L"%s (%d)", keyname(wch), wch);
			update_debug();
			handle_keycode(wch);
		}
		break;
	}

	return true;
}

static void display_handler(const wchar_t *wstr, size_t wlen,
						size_t pos, void *user_data)
{
	const char *prompt = prompt_list[prompt_idx];
	size_t prompt_len = strlen(prompt);
	int prompt_attr = COLOR_PAIR(prompt_color[prompt_idx]);
	int y;

	y = getcury(main_win);
	wmove(main_win, y, 0);
	wattron(main_win, prompt_attr);
	waddnstr(main_win, prompt, prompt_len);
	wattroff(main_win, prompt_attr);
	if (wlen > 0) {
		if (masked_input) {
			char *tmp = l_malloc(wlen);
			memset(tmp, '*', wlen);
			waddnstr(main_win, tmp, wlen);
			l_free(tmp);
		} else
			waddnwstr(main_win, wstr, wlen);
	}
	wclrtoeol(main_win);

	if (!curs_visibility)
		mvwchgat(main_win, y, prompt_len + pos, 1, A_COLOR, 2, NULL);
	wmove(main_win, y, prompt_len + pos);

	wrefresh(main_win);
}

static void debug_handler(const char *str, void *user_data)
{
	wmove(info_win, 12, 0);
	if (str)
		waddstr(info_win, str);
	wclrtobot(info_win);

	wnoutrefresh(info_win);
	wnoutrefresh(main_win);
	doupdate();
}

int main(int argc, char *argv[])
{
	struct l_io *stdin_io;
	struct l_timeout *update_to;
	int exit_status;

	l_main_init();

	init_display();

	edit = l_edit_new();
	l_edit_set_debug_handler(edit, debug_handler, NULL);
	l_edit_set_max_input_length(edit, input_len_list[input_len_idx]);
	l_edit_set_history_size(edit, history_size_list[history_size_idx]);
	l_edit_set_display_handler(edit, display_handler, NULL);
	l_edit_history_load(edit, history_pathname);

	resize_display();
	update_debug();
	update_status();

	stdin_io = l_io_new(STDIN_FILENO);
	l_io_set_read_handler(stdin_io, stdin_callback, NULL, NULL);

	update_to = l_timeout_create(UPDATE_RATE, update_callback, NULL, NULL);

	exit_status = l_main_run();

	l_timeout_remove(update_to);

	l_io_destroy(stdin_io);

	l_edit_free(edit);

	reset_display();

	l_main_exit();

	return exit_status;
}

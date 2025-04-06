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
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include "private.h"
#include "string.h"
#include "edit.h"

#define DEFAULT_BUFFER_SIZE	(15)

struct input_buf {
	wchar_t *buf;
	size_t size;
	size_t len;
	size_t pos;
	struct input_buf *next;
};

struct l_edit {
	struct input_buf *head;
	struct input_buf *main;
	size_t list_count;
	size_t max_list_size;
	size_t max_input_len;
	size_t max_display_len;
	l_edit_display_func_t display_handler;
	void *display_data;
	l_edit_debug_func_t debug_handler;
	void *debug_data;
};

static inline size_t next_power(size_t len)
{
	size_t n = 1;

	if (len > SIZE_MAX / 2)
		return SIZE_MAX;

	while (n < len)
		n = n << 1;

	return n;
}

static void grow_input_buf(struct input_buf *buf, size_t extra)
{
	if (buf->len + extra < buf->size)
		return;

	buf->size = next_power(buf->len + extra + 1);
	buf->buf = l_realloc(buf->buf, sizeof(wchar_t) * buf->size);
}

static struct input_buf *alloc_sized_input_buf(size_t initial_size)
{
	struct input_buf *buf;

	buf = l_new(struct input_buf, 1);

	/* Set up new input buffer with initial size */
	buf->size = initial_size + 1;
	buf->buf = l_malloc(sizeof(wchar_t) * buf->size);
	buf->buf[0] = L'\0';
	buf->pos = 0;
	buf->len = 0;
	buf->next = NULL;

	return buf;
}

static struct input_buf *alloc_duplicate_input_buf(struct input_buf *ref)
{
	struct input_buf *buf;

	if (!ref)
		return NULL;

	buf = l_new(struct input_buf, 1);

	/* Set up new input buffer and copy from the reference */
	buf->size = ref->len;
	buf->buf = wcsdup(ref->buf);
	buf->pos = ref->len;
	buf->len = ref->len;
	buf->next = NULL;

	return buf;
}

static void reset_input_buf(struct input_buf *buf, const char *input)
{
	if (input) {
		size_t len;

		/* Calculate the required size of the wide character string
		 * including its terminating null character.
		 */
		len = mbstowcs(NULL, input, 0) + 1;

		/* If the current buffer is to small, then allocate a new
		 * one and free the previous one. Since in most cases the
		 * data is different, there is no need for using re-alloc
		 * procedure here.
		 */
		if (len > buf->size) {
			l_free(buf->buf);

			buf->size = len;
			buf->buf = l_malloc(sizeof(wchar_t) * buf->size);
		}

		/* Convert the multibyte input into a wide character string
		 * and then move the cursor to the end.
		 */
		buf->len = mbstowcs(buf->buf, input, buf->size);
		buf->pos = buf->len;
	} else {
		/* Reset the main item to an empty string */
		buf->buf[0] = L'\0';
		buf->pos = 0;
		buf->len = 0;
	}
}

static void enforce_max_input_len(struct input_buf *buf, size_t max_len)
{
	/* When no limit is set, then nothing to do here */
	if (max_len == 0)
		return;

	/* If the current buffer is to large, then truncate it and move
	 * the cursor to the end if needed.
	 */
	if (buf->len > max_len) {
		buf->len = max_len;
		if (buf->pos > buf->len)
			buf->pos = buf->len;
		buf->buf[buf->len] = L'\0';
	}
}

static void free_input_buf(struct input_buf *buf)
{
	l_free(buf->buf);
	l_free(buf);
}

LIB_EXPORT struct l_edit *l_edit_new(void)
{
	static size_t initial_size = 15;
	struct l_edit *edit;

	edit = l_new(struct l_edit, 1);

	edit->head = alloc_sized_input_buf(initial_size);
	edit->main = edit->head;
	edit->list_count = 0;
	edit->max_list_size = 0;
	edit->max_input_len = 0;
	edit->max_display_len = 0;

	return edit;
}

LIB_EXPORT void l_edit_free(struct l_edit *edit)
{
	struct input_buf *buf;

	if (!edit)
		return;

	buf = edit->head;
	while (buf) {
		struct input_buf *tmp = buf->next;
		free_input_buf(buf);
		buf = tmp;
	}

	l_free(edit);
}

static void update_debug(struct l_edit *edit)
{
	struct input_buf *buf;
	struct l_string *str;
	char *tmp;
	size_t len;
	unsigned int pos = 0;

	if (!edit->debug_handler)
		return;

	str = l_string_new(edit->head->len + 32);

	l_string_append_printf(str, "Display : %zu\n", edit->max_display_len);
	l_string_append_printf(str, "Buffer  : %zu\n", edit->main->size);
	if (edit->max_input_len)
		l_string_append_printf(str, "Input   : %zu/%zu\n",
					edit->main->len, edit->max_input_len);
	else
		l_string_append_printf(str, "Input   : %zu/unlimited\n",
							edit->main->len);
	l_string_append_printf(str, "Cursor  : %zu\n", edit->main->pos);
	l_string_append_printf(str, "History : %zu/%zu\n",
				edit->list_count, edit->max_list_size);

	buf = edit->head;
	while (buf) {
		len = wcstombs(NULL, buf->buf, 0) + 1;
		tmp = l_malloc(len);
		wcstombs(tmp, buf->buf, len);
		l_string_append_printf(str, "%3u %s\n", pos, tmp);
		l_free(tmp);
		pos++;
		buf = buf->next;
	}

	tmp = l_string_unwrap(str);

	edit->debug_handler(edit, tmp, edit->debug_data);

	l_free(tmp);
}

LIB_EXPORT bool l_edit_set_debug_handler(struct l_edit *edit,
				l_edit_debug_func_t handler, void *user_data)
{
	if (!edit)
		return false;

	edit->debug_handler = handler;
	edit->debug_data = user_data;

	update_debug(edit);

	return true;
}

static void update_display(struct l_edit *edit)
{
	const wchar_t *buf = edit->main->buf;
	size_t len = edit->main->len;
	size_t pos = edit->main->pos;

	if (!edit->display_handler)
		return;

	if (edit->max_display_len > 0) {
		/* Move buffer until current position is in display size */
		while (pos >= edit->max_display_len) {
			buf++;
			len--;
			pos--;
		}

		/* Reduce the length until it fits in display size */
		while (len > edit->max_display_len)
			len--;
	}

	edit->display_handler(edit, buf, len, pos, edit->display_data);

	update_debug(edit);
}

LIB_EXPORT bool l_edit_set_display_handler(struct l_edit *edit,
				l_edit_display_func_t handler, void *user_data)
{
	if (!edit)
		return false;

	edit->display_handler = handler;
	edit->display_data = user_data;

	update_display(edit);

	return true;
}

LIB_EXPORT bool l_edit_set_max_display_length(struct l_edit *edit, size_t len)
{
	if (!edit)
		return false;

	edit->max_display_len= len;

	update_display(edit);

	return true;
}

LIB_EXPORT bool l_edit_set_max_input_length(struct l_edit *edit, size_t len)
{
	if (!edit)
		return false;

	/* When switching to unlimited input length, then nothing is there
	 * do to, except storing the value. Refreshing the display is not
	 * needed since everything is already present.
	 */
	if (len == 0) {
		edit->max_input_len = 0;
		update_debug(edit);
		return true;
	}

	edit->max_input_len = len;

	if (edit->main->len > edit->max_input_len) {
		/* If the current length is longer, then it is required to
		 * truncate and if needed move the cursor to the end.
		 */
		edit->main->len = edit->max_input_len;
		if (edit->main->pos > edit->main->len)
			edit->main->pos = edit->main->len;
		edit->main->buf[edit->main->len] = L'\0';
		update_display(edit);
	} else {
		/* Since nothing has to be updated for the display, make
		 * sure the debug output is updated manually.
		 */
		update_debug(edit);
	}

	return true;
}

LIB_EXPORT bool l_edit_set_history_size(struct l_edit *edit, unsigned int size)
{
	if (!edit)
		return false;

	edit->max_list_size = size;

	if (edit->list_count > edit->max_list_size) {
		struct input_buf *buf = edit->head;
		struct input_buf *last;
		size_t count = 0;

		/* Truncating the history means, thattthe last still valid
		 * entry needs to be found.
		 */
		while (count < edit->max_list_size) {
			if (!buf->next)
				break;
			count++;
			buf = buf->next;
		}

		/* Terminate the list on the last item and store it for
		 * later use.
		 */
		last = buf;
		buf = last->next;
		last->next = NULL;

		/* Now free the tail of the list. In case the history index
		 * was present in the tail, move it to the last item.
		 */
		while (buf) {
			struct input_buf *tmp = buf->next;
			if (buf == edit->main)
				edit->main = last;
			free_input_buf(buf);
			buf = tmp;
		}

		edit->list_count = count;
	}

	update_display(edit);

	return true;
}

LIB_EXPORT bool l_edit_refresh(struct l_edit *edit)
{
	if (!edit)
		return false;

	update_display(edit);

	return true;
}

LIB_EXPORT bool l_edit_is_empty(struct l_edit *edit)
{
	if (!edit)
		return true;

	return (edit->main->len == 0);
}

LIB_EXPORT char *l_edit_enter(struct l_edit *edit)
{
	struct input_buf *buf;
	char *str;
	size_t len;

	if (!edit)
		return NULL;

	/* Convert the wide character string into the multibyte string
	 * representation like UTF-8 for example.
	 */
	len = wcstombs(NULL, edit->main->buf, 0) + 1;
	str = l_malloc(len);
	wcstombs(str, edit->main->buf, len);

	if (edit->main->len > 0) {
		/* If the current entered item is different from the first
		 * one in history (if history is present), then allocate
		 * a copy of that item and push it to the head of the
		 * history list.
		 */
		if (!edit->head->next || wcscmp(edit->main->buf,
						edit->head->next->buf)) {
			buf = alloc_duplicate_input_buf(edit->main);
			buf->next = edit->head->next;
			edit->head->next = buf;
			edit->list_count++;
		}

		/* Reset the head item, since that becomes the next
		 * main input item.
		 */
		edit->head->buf[0] = L'\0';
		edit->head->pos = 0;
		edit->head->len = 0;

		/* If the history size has grown to large, remove the
		 * last item from the list.
		 */
		if (edit->list_count > edit->max_list_size) {
			buf = edit->head;
			while (buf->next) {
				if (!buf->next->next) {
					free_input_buf(buf->next);
					buf->next = NULL;
					edit->list_count--;
					break;
				}
				buf = buf->next;
			}
		}
	}

	edit->main = edit->head;
	update_display(edit);

	return str;
}

LIB_EXPORT bool l_edit_reset(struct l_edit *edit, const char *input)
{
	if (!edit)
		return false;

	/* Reset the main item back to the head of the history before
	 * resetting it or overwriting it with the provided input.
	 */
	edit->main = edit->head;

	reset_input_buf(edit->main, input);
	update_display(edit);

	return true;
}

LIB_EXPORT bool l_edit_insert(struct l_edit *edit, wint_t ch)
{
	if (!edit)
		return false;

	/* Check if the max input length has already been reached */
	if (edit->max_input_len && edit->main->len >= edit->max_input_len)
		return false;

	/* This will magically grow the buffer to make room for at least
	 * one wide character.
	 */
	grow_input_buf(edit->main, 1);

	/* If length is already the same as the max size of a possible
	 * string, there is nothing more to add.
	 */
	if (edit->main->len == SIZE_MAX)
		return false;

	/* If the cursor is not at the end, the new character has to be
	 * inserted and for thus the tail portion needs to move one
	 * character back.
	 */
	if (edit->main->len != edit->main->pos)
		wmemmove(edit->main->buf + edit->main->pos + 1,
				edit->main->buf + edit->main->pos,
				edit->main->len - edit->main->pos);
	edit->main->buf[edit->main->pos] = ch;
	edit->main->pos++;
	edit->main->len++;
	edit->main->buf[edit->main->len] = L'\0';
	update_display(edit);

	return true;
}

LIB_EXPORT bool l_edit_delete(struct l_edit *edit)
{
	if (!edit)
		return false;

	/* If the cursor is not at the end, deletion of a character means
	 * that the tail moves one character forward.
	 */
	if (edit->main->len > 0 && edit->main->pos < edit->main->len) {
		wmemmove(edit->main->buf + edit->main->pos,
				edit->main->buf + edit->main->pos + 1,
				edit->main->len - edit->main->pos - 1);
		edit->main->len--;
		edit->main->buf[edit->main->len] = L'\0';
		update_display(edit);
	}

	return true;
}

LIB_EXPORT bool l_edit_delete_all(struct l_edit *edit)
{
	if (!edit)
		return false;

	/* Keep the buffer allocated, but reset it to an empty string */
	edit->main->buf[0] = L'\0';
	edit->main->pos = 0;
	edit->main->len = 0;
	update_display(edit);

	return true;
}

LIB_EXPORT bool l_edit_truncate(struct l_edit *edit)
{
	if (!edit)
		return false;

	/* Keep the buffer allocated, but truncate after the cursor */
	edit->main->buf[edit->main->pos] = L'\0';
	edit->main->len = edit->main->pos;
	update_display(edit);

	return true;
}

LIB_EXPORT bool l_edit_backspace(struct l_edit *edit)
{
	if (!edit)
		return false;

	/* If the cursor is not at the beginning, the backspace operation
	 * means that tail has to move one character forward.
	 */
	if (edit->main->pos > 0 && edit->main->len > 0) {
	        wmemmove(edit->main->buf + edit->main->pos - 1,
				edit->main->buf + edit->main->pos,
				edit->main->len - edit->main->pos);
		edit->main->pos--;
		edit->main->len--;
		edit->main->buf[edit->main->len] = L'\0';
		update_display(edit);
	}

	return true;
}

LIB_EXPORT bool l_edit_move_left(struct l_edit *edit)
{
	if (!edit)
		return false;

	/* If the cursor is not at the beginning, then move it one back */
	if (edit->main->pos > 0) {
		edit->main->pos--;
		update_display(edit);
	}

	return true;
}

LIB_EXPORT bool l_edit_move_right(struct l_edit *edit)
{
	if (!edit)
		return false;

	/* If the cursor is not at the end, then move it one forward */
	if (edit->main->pos != edit->main->len) {
		edit->main->pos++;
		update_display(edit);
	}

	return true;
}

LIB_EXPORT bool l_edit_move_home(struct l_edit *edit)
{
	if (!edit)
		return false;

	/* If the cursor is not at the beginning, move it there */
	if (edit->main->pos != 0) {
		edit->main->pos = 0;
		update_display(edit);
	}

	return true;
}

LIB_EXPORT bool l_edit_move_end(struct l_edit *edit)
{
	if (!edit)
		return false;

	/* If the cursor is not at the end, move it there */
	if (edit->main->pos != edit->main->len) {
		edit->main->pos = edit->main->len;
		update_display(edit);
	}

	return true;
}

LIB_EXPORT bool l_edit_history_backward(struct l_edit *edit)
{
	if (!edit)
		return false;

	/* If there is another item in the history list, move the main
	 * item to that and enforce the max input length on the new item.
	 */
	if (edit->main->next) {
		edit->main = edit->main->next;
		enforce_max_input_len(edit->main, edit->max_input_len);
		update_display(edit);
	}

	return true;
}

LIB_EXPORT bool l_edit_history_forward(struct l_edit *edit)
{
	struct input_buf *buf;

	if (!edit)
		return false;

	/* Walk the list of history items until the current main item
	 * matches the next item, then move the main item to current
	 * item and ensure that the max input length requirement is met.
	 */
	for (buf = edit->head; buf; buf = buf->next) {
		if (buf->next == edit->main) {
			edit->main = buf;
			enforce_max_input_len(edit->main, edit->max_input_len);
			update_display(edit);
			break;
		}
	}

	return true;
}

LIB_EXPORT bool l_edit_history_load(struct l_edit *edit, const char *pathname)
{
	static size_t initial_line_size = 16;
	struct input_buf *buf;
	struct l_string *str;
	size_t count;
	int fd;

	if (!edit)
		return false;

	if (!pathname)
		return false;

	if (!edit->max_list_size)
		return true;

	fd = open(pathname, O_RDONLY);
	if (fd < 0)
		return false;

	str = l_string_new(initial_line_size);

	buf = edit->head;
	count = 0;

	while (count < edit->max_list_size) {
		char *tmp;
		char ch;
		int res;

		res = read(fd, &ch, 1);
		if (res != 1)
			break;

		if (ch != '\n') {
			l_string_append_c(str, ch);
			continue;
		}

		tmp = l_string_unwrap(str);

		/* If there is not next item, but max count has not yet
		 * reached a new items is created. Otherwise the existing
		 * item is overwritten.
		 */
		if (!buf->next)
			buf->next = alloc_sized_input_buf(0);

		/* Fill the item with input from the history file */
		reset_input_buf(buf->next, tmp);
		buf = buf->next;
		count++;

		l_free(tmp);

		str = l_string_new(initial_line_size);
	}

	l_string_free(str);

	close(fd);

	edit->list_count = count;
	update_display(edit);

	return true;
}

LIB_EXPORT bool l_edit_history_save(struct l_edit *edit, const char *pathname)
{
	struct input_buf *buf;
	int fd;

	if (!edit)
		return false;

	if (!pathname)
		return false;

	fd = open(pathname, O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR|S_IWUSR);
	if (fd < 0)
		return false;

	buf = edit->head->next;

	while (buf) {
		char *tmp;
		size_t len;

		len = wcstombs(NULL, buf->buf, 0) + 1;
		tmp = l_malloc(len);
		wcstombs(tmp, buf->buf, len);
		dprintf(fd, "%s\n", tmp);
		l_free(tmp);

		buf = buf->next;
	}

	close(fd);

	return true;
}

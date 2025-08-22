/*
 * Embedded Linux library
 * Copyright (C) 2023  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef __ELL_EDIT_H
#define __ELL_EDIT_H

#include <stdbool.h>
#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

struct l_edit;

struct l_edit *l_edit_new(void);
void l_edit_free(struct l_edit *edit);

typedef void (*l_edit_debug_func_t) (const char *str, void *user_data);

bool l_edit_set_debug_handler(struct l_edit *edit,
				l_edit_debug_func_t handler, void *user_data);

typedef void (*l_edit_display_func_t) (const wchar_t *wstr, size_t wlen,
						size_t pos, void *user_data);

bool l_edit_set_display_handler(struct l_edit *edit,
				l_edit_display_func_t handler, void *user_data);

bool l_edit_set_max_display_length(struct l_edit *edit, size_t len);
bool l_edit_set_max_input_length(struct l_edit *edit, size_t len);
bool l_edit_set_history_size(struct l_edit *edit, unsigned int size);
bool l_edit_refresh(struct l_edit *edit);
bool l_edit_is_empty(struct l_edit *edit);
char *l_edit_enter(struct l_edit *edit);
bool l_edit_reset(struct l_edit *edit, const char *input);
bool l_edit_insert(struct l_edit *edit, wint_t ch);
bool l_edit_delete(struct l_edit *edit);
bool l_edit_delete_all(struct l_edit *edit);
bool l_edit_truncate(struct l_edit *edit);
bool l_edit_backspace(struct l_edit *edit);
bool l_edit_move_left(struct l_edit *edit);
bool l_edit_move_right(struct l_edit *edit);
bool l_edit_move_home(struct l_edit *edit);
bool l_edit_move_end(struct l_edit *edit);
bool l_edit_history_backward(struct l_edit *edit);
bool l_edit_history_forward(struct l_edit *edit);
bool l_edit_history_load(struct l_edit *edit, const char *pathname);
bool l_edit_history_save(struct l_edit *edit, const char *pathname);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_EDIT_H */

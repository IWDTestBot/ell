/*
 * Embedded Linux library
 * Copyright (C) 2023  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef __ELL_TERM_H
#define __ELL_TERM_H

#include <stdbool.h>
#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

struct l_term;

struct l_term *l_term_new(void);
void l_term_free(struct l_term *term);

bool l_term_set_input_stdin(struct l_term *term);
bool l_term_set_output_stdout(struct l_term *term);

typedef void (*l_term_key_func_t) (wint_t wch, void *user_data);

bool l_term_set_key_handler(struct l_term *term,
				l_term_key_func_t handler, void *user_data);

bool l_term_open(struct l_term *term);
bool l_term_close(struct l_term *term);

bool l_term_putnstr(struct l_term *term, const char *str, size_t n);
bool l_term_putstr(struct l_term *term, const char *str);
bool l_term_putchar(struct l_term *term, int ch);

bool l_term_get_max_columns(struct l_term *term, unsigned short *cols);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_TERM_H */

/*
 * Embedded Linux library
 * Copyright (C) 2023-2024  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef __ELL_TERM_H
#define __ELL_TERM_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

struct l_term;

struct l_term *l_term_new(void);
void l_term_free(struct l_term *term);

typedef void (*l_term_io_func_t)(struct l_term *term,
                                 int fd,
                                 bool readable,
                                 bool writable,
                                 void *user_data);

int  l_term_set_io_handler(struct l_term *term,
                           l_term_io_func_t handler,
                           void *user_data);

int  l_term_set_input(struct l_term *term, int fd);
int  l_term_set_output(struct l_term *term, int fd);

int  l_term_set_input_stdin(struct l_term *term);
int  l_term_set_output_stdout(struct l_term *term);

typedef void (*l_term_key_func_t) (struct l_term *term, wint_t wch, void *user_data);

int  l_term_set_key_handler(struct l_term *term,
				l_term_key_func_t handler, void *user_data);

int  l_term_open(struct l_term *term);
int  l_term_close(struct l_term *term);

bool l_term_io_callback(struct l_io *io, void *user_data);

void l_term_process(struct l_term *term);

int  l_term_putnstr(struct l_term *term, const char *str, size_t n);
int  l_term_putstr(struct l_term *term, const char *str);
int  l_term_putchar(struct l_term *term, int ch);
int  l_term_print(struct l_term *term, const char *str, ...);
int  l_term_vprint(struct l_term *term, const char *str, va_list ap);

int  l_term_set_bounds(struct l_term *term, uint16_t rows, uint16_t columns);

int  l_term_get_rows(struct l_term *term, uint16_t *rows);
int  l_term_get_columns(struct l_term *term, uint16_t *columns);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_TERM_H */

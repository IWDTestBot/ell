/*
 * Embedded Linux library
 * Copyright (C) 2019  Geanix
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef __ELL_GPIO_H
#define __ELL_GPIO_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct l_gpio_chip;
struct l_gpio_writer;
struct l_gpio_reader;

char **l_gpio_chips_with_line_label(const char *line_label);
struct l_gpio_chip *l_gpio_chip_new(const char *chip_name);
void l_gpio_chip_free(struct l_gpio_chip *chip);
const char *l_gpio_chip_get_label(struct l_gpio_chip *chip);
const char *l_gpio_chip_get_name(struct l_gpio_chip *chip);
uint32_t l_gpio_chip_get_num_lines(struct l_gpio_chip *chip);
bool l_gpio_chip_find_line_offset(struct l_gpio_chip *chip,
					const char *line_label,
					uint32_t *line_offset);
char *l_gpio_chip_get_line_label(struct l_gpio_chip *chip, uint32_t offset);
char *l_gpio_chip_get_line_consumer(struct l_gpio_chip *chip, uint32_t offset);

struct l_gpio_writer *l_gpio_writer_new(struct l_gpio_chip *chip,
					const char *consumer,
					uint32_t n_offsets,
					const uint32_t offsets[],
					const uint32_t values[]);
void l_gpio_writer_free(struct l_gpio_writer *writer);
bool l_gpio_writer_set(struct l_gpio_writer *writer, uint32_t n_values,
			const uint32_t values[]);

struct l_gpio_reader *l_gpio_reader_new(struct l_gpio_chip *chip,
					const char *consumer,
					uint32_t n_offsets,
					const uint32_t offsets[]);
void l_gpio_reader_free(struct l_gpio_reader *reader);
bool l_gpio_reader_get(struct l_gpio_reader *reader, uint32_t n_values,
			uint32_t values[]);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_GPIO_H */

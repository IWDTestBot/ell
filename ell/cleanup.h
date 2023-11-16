/*
 * Embedded Linux library
 * Copyright (C) 2021  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#define DEFINE_CLEANUP_FUNC(func, arg_type)			\
	inline __attribute__((always_inline))		\
	void func ## _cleanup(void *p) { func((arg_type)(*(void **) p)); }

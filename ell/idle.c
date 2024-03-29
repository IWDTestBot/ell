/*
 * Embedded Linux library
 * Copyright (C) 2011-2014  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>

#include "useful.h"
#include "idle.h"
#include "main-private.h"
#include "private.h"

/**
 * SECTION:idle
 * @short_description: Idle processing support
 *
 * Idle processing support
 */

/**
 * l_idle:
 *
 * Opaque object representing the idle time event.
 */
struct l_idle {
	union {
		l_idle_notify_cb_t callback;
		l_idle_oneshot_cb_t oneshot;
	};

	l_idle_destroy_cb_t destroy;
	void *user_data;
	int id;
};

static void idle_destroy(void *user_data)
{
	struct l_idle *idle = user_data;

	if (idle->destroy)
		idle->destroy(idle->user_data);

	l_free(idle);
}

static void idle_callback(void *user_data)
{
	struct l_idle *idle = user_data;

	if (idle->callback)
		idle->callback(idle, idle->user_data);
}

static void oneshot_callback(void *user_data)
{
	struct l_idle *idle = user_data;

	if (idle->oneshot)
		idle->oneshot(idle->user_data);

	idle_remove(idle->id);
}

/**
 * l_idle_create:
 * @callback: idle callback function
 * @user_data: user data provided to idle callback function
 * @destroy: destroy function for user data
 *
 * Create a new idle event processing object.
 *
 * The idle callback will be called until canceled using l_idle_remove().
 *
 * Returns: a newly allocated #l_idle object
 **/
LIB_EXPORT struct l_idle *l_idle_create(l_idle_notify_cb_t callback,
			void *user_data, l_idle_destroy_cb_t destroy)
{
	struct l_idle *idle;

	if (unlikely(!callback))
		return NULL;

	idle = l_new(struct l_idle, 1);

	idle->callback = callback;
	idle->destroy = destroy;
	idle->user_data = user_data;

	idle->id = idle_add(idle_callback, idle, 0, idle_destroy);
	if (idle->id < 0) {
		l_free(idle);
		return NULL;
	}

	return idle;
}

/**
 * l_idle_oneshot:
 * @callback: idle callback function
 * @user_data: user data provided to idle callback function
 * @destroy: destroy function for user data
 *
 * Create a new idle event processing object.  The callback will be called
 * only once at which point the object will be destroyed.
 *
 * Returns: true if the oneshot idle object could be created successfully.
 **/
LIB_EXPORT bool l_idle_oneshot(l_idle_oneshot_cb_t callback, void *user_data,
				l_idle_destroy_cb_t destroy)
{
	struct l_idle *idle;

	if (unlikely(!callback))
		return NULL;

	idle = l_new(struct l_idle, 1);

	idle->oneshot = callback;
	idle->destroy = destroy;
	idle->user_data = user_data;

	idle->id = idle_add(oneshot_callback, idle,
				IDLE_FLAG_NO_WARN_DANGLING, idle_destroy);
	if (idle->id < 0) {
		l_free(idle);
		return false;
	}

	return true;
}
/**
 * l_idle_remove:
 * @idle: idle object
 *
 * Remove idle event processing object.
 **/
LIB_EXPORT void l_idle_remove(struct l_idle *idle)
{
	if (unlikely(!idle))
		return;

	idle_remove(idle->id);
}

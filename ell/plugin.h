/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef __ELL_PLUGIN_H
#define __ELL_PLUGIN_H

#ifdef __cplusplus
extern "C" {
#endif

#define L_PLUGIN_PRIORITY_LOW      -100
#define L_PLUGIN_PRIORITY_DEFAULT     0
#define L_PLUGIN_PRIORITY_HIGH      100

struct l_plugin_desc {
	const char *name;
	const char *description;
	const char *version;
	int priority;
	int (*init) (void);
	void (*exit) (void);
};

#define L_PLUGIN_DEFINE(symbol, name, description, version, \
						priority, init, exit) \
		extern struct l_plugin_desc symbol \
				__attribute__ ((visibility("default"))); \
		struct l_plugin_desc symbol = { \
			#name, description, version, priority, init, exit \
		};

void l_plugin_add(const struct l_plugin_desc *desc, const char *version);

void l_plugin_load(const char *pattern, const char *symbol,
						const char *version);
void l_plugin_unload(void);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_PLUGIN_H */

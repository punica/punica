/*
 * Punica - LwM2M server with REST API
 * Copyright (C) 2019 8devices
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 */

#ifndef PUNICA_PLUGIN_MANAGER_BASIC_PLUGIN_MANAGER_H
#define PUNICA_PLUGIN_MANAGER_BASIC_PLUGIN_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "../linked_list.h"
#include "basic_core.h"

static const size_t J_MAX_LENGTH_PLUGIN_NAME = 1024;
static const size_t J_MAX_LENGTH_PLUGIN_PATH = 1024;

typedef struct
{
    const char *name;
    const char *path;
} plugin_settings_t;

typedef struct
{
    linked_list_t *plugins_list;
} plugins_settings_t;

struct basic_plugin_manager_t;
typedef struct basic_plugin_manager_t basic_plugin_manager_t;

basic_plugin_manager_t *basic_plugin_manager_new(basic_punica_core_t *core);
void basic_plugin_manager_delete(basic_plugin_manager_t *c_manager);

int basic_plugin_manager_load_plugin(basic_plugin_manager_t *c_manager,
                                     const char *path,
                                     const char *name);
int basic_plugin_manager_unload_plugin(basic_plugin_manager_t *c_manager,
                                       const char *name);

int basic_plugin_manager_load_plugins(basic_plugin_manager_t *plugin_manager,
                                      plugins_settings_t *plugins_settings);
int basic_plugin_manager_unload_plugins(basic_plugin_manager_t *plugin_manager,
                                        plugins_settings_t *plugins_settings);

#ifdef __cplusplus
}
#endif

#endif // PUNICA_PLUGIN_MANAGER_BASIC_PLUGIN_MANAGER_H

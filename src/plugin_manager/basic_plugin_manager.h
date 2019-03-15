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

#include "basic_core.h"

enum
{
    J_MAX_LENGTH_PLUGIN_NAME = 1024,
    J_MAX_LENGTH_PLUGIN_PATH = 1024,
};

struct basic_plugin_manager_t;
typedef struct basic_plugin_manager_t basic_plugin_manager_t;

basic_plugin_manager_t *basic_plugin_manager_new(basic_punica_core_t *c_manager_core);
void basic_plugin_manager_delete(basic_plugin_manager_t *c_manager);

int basic_plugin_manager_load_plugin(basic_plugin_manager_t *c_manager,
                                     const char *c_path,
                                     const char *c_name);
int basic_plugin_manager_unload_plugin(basic_plugin_manager_t *c_manager,
                                       const char *c_name);

#endif // PUNICA_PLUGIN_MANAGER_BASIC_PLUGIN_MANAGER_H

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

#ifndef PLUGIN_API_HPP
#define PLUGIN_API_HPP

#include "plugin.hpp"
#include "plugin_manager_core.hpp"

#define PLUGIN_HANDLE_NAME "PLUGIN_API"

typedef Plugin * (*plugin_create_t)(PluginManagerCore *core);
typedef void (*plugin_destroy_t)(Plugin *plugin);

typedef struct
{
    uint32_t major:8,
             minor:8,
             revision:16;
} plugin_version_t;

typedef struct
{
    plugin_version_t version;
    plugin_create_t create;
    plugin_destroy_t destroy;
} plugin_api_t;

#endif // PLUGIN_API_HPP

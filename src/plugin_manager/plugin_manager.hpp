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

#ifndef PUNICA_PLUGIN_MANAGER_PLUGIN_MANAGER_HPP
#define PUNICA_PLUGIN_MANAGER_PLUGIN_MANAGER_HPP

#include <list>
#include <string>

#include <punica/core.hpp>
#include <punica/plugin_manager/plugin_api.hpp>
#include <punica/plugin_manager/plugin.hpp>

class PluginManager
{
public:
    virtual ~PluginManager() { }

    virtual bool loadPlugin(std::string name, std::string path) = 0;
    virtual bool unloadPlugin(std::string name) = 0;

protected:
    PluginManagerCore *core;
    std::map<std::string, std::pair<Plugin *, plugin_api_t *> > plugins;
};

#endif // PUNICA_PLUGIN_MANAGER_PLUGIN_MANAGER_HPP 

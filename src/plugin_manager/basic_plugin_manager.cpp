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

#include "basic_plugin_manager.hpp"
#include "basic_plugin_manager.h"

#include "basic_core.hpp"

basic_plugin_manager_t *basic_plugin_manager_new(basic_punica_core_t *c_core)
{
    punica::Core::ptr core(reinterpret_cast<BasicCore *>(c_core));

    return reinterpret_cast<basic_plugin_manager_t *>(
               new BasicPluginManager(core));
}

void basic_plugin_manager_delete(basic_plugin_manager_t *c_manager)
{
    delete reinterpret_cast<BasicPluginManager *>(c_manager);
}

int basic_plugin_manager_load_plugin(basic_plugin_manager_t *c_manager,
                                     const char *c_path,
                                     const char *c_name)
{
    BasicPluginManager *manager =
        reinterpret_cast<BasicPluginManager *>(c_manager);
    const std::string path(c_path);
    const std::string name(c_name);

    return static_cast<int>(manager->loadPlugin(path, name));
}

int basic_plugin_manager_unload_plugin(basic_plugin_manager_t *c_manager,
                                       const char *c_name)
{
    BasicPluginManager *manager =
        reinterpret_cast<BasicPluginManager *>(c_manager);
    const std::string name(c_name);

    return static_cast<int>(manager->unloadPlugin(name));
}

BasicPluginManager::BasicPluginManager(punica::Core::ptr core):
    mCore(core),
    mPlugins()
{ }

BasicPluginManager::~BasicPluginManager()
{
    mPlugins.clear();
}

bool BasicPluginManager::loadPlugin(std::string path, std::string name)
{
    BasicPluginWrapper::ptr plugin(new BasicPluginWrapper(path, name));
    if (plugin->loadPlugin(mCore) != true)
    {
        return false;
    }

    if (mPlugins.find(name) != mPlugins.end())
    {
        unloadPlugin(name);
    }

    mPlugins[name] = std::move(plugin);

    return true;
}

bool BasicPluginManager::unloadPlugin(std::string name)
{
    BasicPluginWrapper::map::iterator pluginsIterator = mPlugins.find(name);

    if (pluginsIterator == mPlugins.end())
    {
        return false;
    }

    mPlugins.erase(pluginsIterator);
    return true;
}

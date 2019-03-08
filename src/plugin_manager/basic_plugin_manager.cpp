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

#include <dlfcn.h>
#include <iostream>

#include "basic_plugin_manager_core.hpp"
#include "basic_plugin_manager.hpp"

#ifdef __cplusplus
extern "C" {
#endif

#include "basic_plugin_manager.h"

CBasicPluginManager *new_BasicPluginManager(CBasicPluginManagerCore *c_manager_core)
{
    BasicPluginManagerCore *manager_core = reinterpret_cast<BasicPluginManagerCore *>(c_manager_core);

    return reinterpret_cast<CBasicPluginManager *>(new BasicPluginManager(manager_core));
}
void delete_BasicPluginManager(CBasicPluginManager *c_manager)
{
    delete reinterpret_cast<BasicPluginManager *>(c_manager);
}
int BasicPluginManager_loadPlugin(CBasicPluginManager *c_manager,
                                  const char *c_path,
                                  const char *c_name)
{
    BasicPluginManager *manager = reinterpret_cast<BasicPluginManager *>(c_manager);
    const std::string path(c_path);
    const std::string name(c_name);

    return static_cast<int>(manager->loadPlugin(path, name));
}
int BasicPluginManager_unloadPlugin(CBasicPluginManager *c_manager,
                                    const char *c_name)
{
    BasicPluginManager *manager = reinterpret_cast<BasicPluginManager *>(c_manager);
    const std::string name(c_name);

    return static_cast<int>(manager->unloadPlugin(name));
}

#ifdef __cplusplus
} // extern "C"
#endif

BasicPluginManager::BasicPluginManager(PluginManagerCore *plugin_core):
    core(plugin_core),
    plugins()
{
}
BasicPluginManager::~BasicPluginManager()
{
    std::map<std::string, std::pair<Plugin *, plugin_api_t *> >::iterator plugins_iterator;

    for (plugins_iterator = plugins.begin(); plugins_iterator != plugins.end(); ++plugins_iterator)
    {
        unloadPlugin(plugins_iterator->first);
    }
}
bool BasicPluginManager::loadPlugin(std::string path, std::string name)
{
    if (plugins.find(name) != plugins.end())
    {
        if (unloadPlugin(name) != true)
        {
            return false;
        }
    }

    void *dll = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (dll == NULL)
    {
        std::cerr << "Failed to load plugin file from '" << path << "\"!" << std::endl;
        return false;
    }

    plugin_api_t *plugin_api = static_cast<plugin_api_t *>(dlsym(dll, PLUGIN_HANDLE_NAME));

    if (plugin_api == NULL)
    {
        std::cerr << "Failed to load plugin api from '" << path << "\"!" << std::endl;
        return false;
    }

    if (plugin_api->create == NULL)
    {
        std::cerr << "Failed to load plugin api from '" << path << "\"!" << std::endl;
        std::cerr << "Missing PLUGIN_API->create()" << std::endl;
        return false;
    }
    if (plugin_api->destroy == NULL)
    {
        std::cerr << "Failed to load plugin api from '" << path << "\"!" << std::endl;
        std::cerr << "Missing PLUGIN_API->destroy()" << std::endl;
        return false;
    }

    plugin_version_t plugin_version = plugin_api->version;
    Plugin *plugin = plugin_api->create(core);

    if (plugin == NULL)
    {
        std::cerr << "Failed to create plugin instance!" << std::endl;
        return false;
    }

    plugins[name] = std::make_pair(plugin, plugin_api);

    return true;
}
bool BasicPluginManager::unloadPlugin(std::string name)
{
    std::map<std::string, std::pair<Plugin *, plugin_api_t *> >::iterator plugins_iterator =
        plugins.find(name);
    Plugin *plugin;
    plugin_api_t *plugin_api;

    if (plugins_iterator == plugins.end())
    {
        return false;
    }

    plugin = plugins_iterator->second.first;
    plugin_api = plugins_iterator->second.second;

    plugin_api->destroy(plugin);

    plugins.erase(plugins_iterator);

    return true;
}
